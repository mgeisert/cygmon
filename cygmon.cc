/*
   cygmon.cc
   Periodically samples PC of a process and its DLLs; writes gprof data files.

   Copyright 2016 Red Hat Inc.

   Written by Mark Geisert <mark@maxrnd.com>, who admits to
   copying liberally from strace.cc.  Props to cgf for strace!

This file is part of Cygwin.

This software is a copyrighted work licensed under the terms of the
Cygwin license.  Please consult the file "CYGWIN_LICENSE" for
details. */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#define cygwin_internal cygwin_internal_dontuse
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../cygwin/include/sys/cygwin.h"
#include "../cygwin/include/cygwin/version.h"
#include "../cygwin/cygtls_padsize.h"
typedef unsigned short u_int16_t;
#include "../cygwin/gmon.h"
#include "path.h"
#undef cygwin_internal

#define SCALE_SHIFT 2     // == 4 bytes of address space per bucket

static const char *pgm;
static int forkdebug = 1;
static int events = 1;
static int new_window;
static char *prefix = (char *) "gmon.out";
static int quiet = -1;
static int samplerate = 100; // in Hz; up to 1000 might work

static int numprocesses;
static DWORD child_pid;
static void *drive_map;

static void
usage (FILE *where = stderr)
{
  fprintf (where, "\
Usage: %s [OPTIONS] <command-line>\n\
Usage: %s [OPTIONS] -p <pid>\n\
\n\
Profiles a command or an existing process\n\
\n\
  -e, --events             display Windows DEBUG_EVENTS (toggle - default true)\n\
  -f, --profile-children   profile child processes (toggle - default true)\n\
  -h, --help               display usage information and exit\n\
  -o, --output=FILENAME    set output file to FILENAME\n\
  -p, --pid=N              attach to executing program with cygwin pid N\n\
  -q, --quiet              suppress messages about attaching, detaching, etc.\n\
  -s, --sample-rate=N      set pc sampling rate to N Hz (default 100)\n\
  -V, --version            display version information and exit\n\
  -w, --new-window         spawn program under test in a new window\n\
\n", pgm, pgm);

  exit (where == stderr ? 1 : 0 );
}

// a span is a memory address range covering an EXE's or DLL's .text segment
struct span_list
{
  WCHAR *name;
  LPVOID base;
  size_t textlo;
  size_t texthi;
  int hitcount;
  int numbuckets;
  short *buckets;
  struct span_list *next;
};

// a thread
struct thread_list
{
  DWORD tid;
  HANDLE hthread;
  struct thread_list *next;
};

// a child is any process being sampled in this run
struct child_list
{
  DWORD pid;
  HANDLE hproc;
  HANDLE hquitevt;
  HANDLE hprofthr;
  volatile int profiling;
  struct thread_list *threads;
  struct span_list *spans;
  struct child_list *next;
};

child_list children;
typedef struct child_list child;

static void
note (const char *fmt, ...)
{
  va_list args;
  char buf[4096];

  va_start (args, fmt);
  vsprintf (buf, fmt, args);
  va_end (args);

  fputs (buf, stderr);
  fflush (stderr);
}

static void
warn (int geterrno, const char *fmt, ...)
{
  va_list args;
  char buf[4096];

  va_start (args, fmt);
  sprintf (buf, "%s: ", pgm);
  vsprintf (strchr (buf, '\0'), fmt, args);
  va_end (args);
  if (geterrno)
    perror (buf);
  else
    {
      fputs (buf, stderr);
      fputs ("\n", stderr);
    }
}

static void __attribute__ ((noreturn))
error (int geterrno, const char *fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  warn (geterrno, fmt, args);
  va_end (args);

  exit (1);
}

static size_t
sample (HANDLE h)
{
  static CONTEXT *context = NULL;

  if (!context)
    {
      context = (CONTEXT *) calloc (1, sizeof (CONTEXT));
      context->ContextFlags = CONTEXT_CONTROL;
    }

  if (-1 == SuspendThread (h))
    return 0ULL;
  if (0 == GetThreadContext (h, context))
    {
//    note ("*** unable to get context for thread %d\n", h);
      return 0ULL;
    }
  if (-1 == ResumeThread (h))
    note ("*** unable to resume thread %d\n", h);

#ifdef _WIN64
  return context->Rip;
#else
  return context->Eip;
#endif
}

static void
bump_bucket (child *c, size_t pc)
{
  span_list *s = c->spans;

//note ("%lu %p\n", c->pid, pc);
  if (pc == 0ULL)
    return;
  while (s)
    {
      if (pc >= s->textlo && pc < s->texthi)
        {
          ++s->buckets[(pc - s->textlo) >> SCALE_SHIFT];
          ++s->hitcount;
          return;
        }
      s = s->next;
    }

  note ("*** pc %p out of range for pid %lu\n", pc, c->pid);
}

// profiler runs on its own thread; each sampled process has separate profiler
static DWORD WINAPI
profiler (void *vp)
{
  child *c = (child *) vp;

  while (c->profiling)
    {
      thread_list *t = c->threads;

      while (t)
        {
          if (t->hthread)
            bump_bucket (c, sample (t->hthread));
          t = t->next;
        }

      if (WaitForSingleObject (c->hquitevt, 1000 / samplerate) == WAIT_OBJECT_0)
        break;
    }

  return 0;
}

static void
start_profiler (child *c)
{
  HANDLE h;
  DWORD tid;

//note ("*** start profiler thread on pid %lu\n", c->pid);
  c->hquitevt = CreateEvent (NULL, TRUE, FALSE, NULL);
  if (!c->hquitevt)
    error (0, "unable to create quit event\n");
  c->profiling = 1;
  c->hprofthr = CreateThread (NULL, 0, profiler, (void *) c, 0, &tid);
  if (!c->hprofthr)
    error (0, "unable to create profiling thread\n");

//SetThreadPriority (c->hprofthr, THREAD_PRIORITY_TIME_CRITICAL);
}

static void
stop_profiler (child *c)
{
//note ("*** stop profiler thread on pid %lu\n", c->pid);
  c->profiling = 0;
  SignalObjectAndWait (c->hquitevt, c->hprofthr, INFINITE, FALSE);
  CloseHandle (c->hquitevt);
  CloseHandle (c->hprofthr);
}

// create a gmon.out file for each EXE or DLL that has at least one sample
static void
dump_profile_data (child *c)
{
  span_list *s = c->spans;
  int fd;
  char filename[MAX_PATH + 1];
  struct gmonhdr hdr;

  while (s)
    {
      if (s->hitcount == 0)
        {
          s = s->next;
          continue;
        }

      if (s->name)
        {
          WCHAR *name = 1 + wcsrchr (s->name, L'\\');
          sprintf (filename, "%s.%d.%ls", prefix, c->pid, name);
        }
      else
        sprintf (filename, "%s.%d", prefix, c->pid);

      fd = open (filename, O_CREAT|O_TRUNC|O_WRONLY|O_BINARY, 0666);
      if (fd < 0)
        error (0, "dump_profile_data: unable to create %s\n", filename);

      memset (&hdr, 0, sizeof (hdr));
      hdr.lpc = s->textlo;
      hdr.hpc = s->texthi;
      hdr.ncnt = s->numbuckets * sizeof (short) + sizeof (hdr);
      hdr.version = GMONVERSION;
      hdr.profrate = samplerate;

      write (fd, &hdr, sizeof (hdr));
      write (fd, s->buckets, hdr.ncnt - sizeof (hdr));
      note ("%d %s written to %s\n", s->hitcount,
            s->hitcount == 1 ? "sample" : "samples", filename);
      close (fd);

      s = s->next;
    }
}

DWORD lastpid = 0;
HANDLE lasth;

static child *
get_child (DWORD pid)
{
  child_list *c;

  for (c = &children; (c = c->next) != NULL;)
    if (c->pid == pid)
      return (child *) c;

  return NULL;
}

static void add_span (DWORD, WCHAR *, LPVOID, HANDLE);

static void
add_child (DWORD pid, LPVOID base, HANDLE hproc)
{
  if (!get_child (pid))
    {
      child_list *c = children.next;
      children.next = (child_list *) calloc (1, sizeof (child_list));
      children.next->next = c;
      lastpid = children.next->pid = pid;
      lasth = children.next->hproc = hproc;
      add_span (pid, NULL, base, hproc);
      start_profiler (children.next);
      numprocesses++;
      if (!quiet)
        note ("Windows process %lu attached\n", pid);
    }
}

static void
remove_child (DWORD pid)
{
  child_list *c;

  if (pid == lastpid)
    lastpid = 0;
  for (c = &children; c->next != NULL; c = c->next)
    if (c->next->pid == pid)
      {
        child_list *c1 = c->next;
        c->next = c1->next;
        stop_profiler (c1);
        dump_profile_data (c1);
        free (c1);
        if (!quiet)
          note ("Windows process %lu detached\n", pid);
        numprocesses--;
        return;
      }

  error (0, "no process id %d found", pid);
}

static void
add_thread (DWORD pid, DWORD tid, HANDLE h)
{
  child *c = get_child (pid);

  if (!c)
    error (0, "add_thread: pid %lu not found\n", pid);

  thread_list *t = (thread_list *) calloc (1, sizeof (thread_list));
  t->tid = tid;
  t->hthread = h;

  t->next = c->threads;
  c->threads = t;
}

static void
remove_thread (DWORD pid, DWORD tid)
{
  child *c = get_child (pid);

  if (!c)
    error (0, "remove_thread: pid %lu not found\n", pid);

  thread_list *t = c->threads;
  while (t)
    {
      if (t->tid == tid)
        {
          t->tid = 0;
          t->hthread = 0;
          return;
        }
      t = t->next;
    }

  error (0, "remove_thread: pid %lu tid %lu not found\n", pid, tid);
}

static void
read_child (void *buf, SIZE_T size, void *addr, HANDLE h)
{
  SIZE_T len;

//note ("read %d bytes at %p from handle %d\n", size, addr, h);
  if (0 == ReadProcessMemory (h, addr, buf, size, &len))
    error (0, "read_child: failed\n");
  if (len != size)
    error (0, "read_child: asked for %d bytes but got %d\n", size, len);
}

static IMAGE_SECTION_HEADER *
find_text_section (LPVOID base, HANDLE h)
{
  char *ptr = (char *) base;
  static IMAGE_SECTION_HEADER asect;
  DWORD lfanew;
  WORD nsects;
  DWORD ntsig;

  IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER *) ptr;
  read_child ((void *) &lfanew, sizeof (lfanew), &idh->e_lfanew, h);
  ptr += lfanew;

  // code handles either 32- or 64-bit headers depending on how this is compiled
  IMAGE_NT_HEADERS *inth = (IMAGE_NT_HEADERS *) ptr;
  read_child ((void *) &ntsig, sizeof (ntsig), &inth->Signature, h);
  if (ntsig != IMAGE_NT_SIGNATURE)
    error (0, "find_text_section: NT signature not found\n");

  read_child ((void *) &nsects, sizeof (nsects), &inth->FileHeader.NumberOfSections, h);
  ptr += sizeof (*inth);

  IMAGE_SECTION_HEADER *ish = (IMAGE_SECTION_HEADER *) ptr;
  for (int i = 0; i < nsects; i++)
    {
      read_child ((void *) &asect, sizeof (asect), ish, h);
      if (0 == memcmp (".text\0\0\0", &asect.Name, 8))
        return &asect;
      ish++;
    }

  error (0, ".text section not found\n");
}

static void
add_span (DWORD pid, WCHAR *name, LPVOID base, HANDLE h)
{
  child *c = get_child (pid);

  if (!c)
    error (0, "add_span: pid %lu not found\n", pid);

  IMAGE_SECTION_HEADER *sect = find_text_section (base, c->hproc);
  span_list *s = (span_list *) calloc (1, sizeof (span_list));
  s->name = wcsdup (name);
  s->base = base;
  s->textlo = sect->VirtualAddress + (size_t) base;
  s->texthi = s->textlo + sect->Misc.VirtualSize;
  s->numbuckets = (s->texthi - s->textlo) >> SCALE_SHIFT;
  s->buckets = (short *) calloc (s->numbuckets, sizeof (short));
//note ("    span %p - %p, size %X, numbuckets %d\n",
//       s->textlo, s->texthi, s->texthi - s->textlo, s->numbuckets);

  s->next = c->spans;
  c->spans = s;
}

#define LINE_BUF_CHUNK 128

class linebuf
{
  size_t alloc;
public:
    size_t ix;
  char *buf;
  linebuf ()
  {
    ix = 0;
    alloc = 0;
    buf = NULL;
  }
 ~linebuf ()
  {
    if (buf)
      free (buf);
  }
  void add (const char *what, int len);
  void add (const char *what)
  {
    add (what, strlen (what));
  }
  void prepend (const char *what, int len);
};

void
linebuf::add (const char *what, int len)
{
  size_t newix;

  if ((newix = ix + len) >= alloc)
    {
      alloc += LINE_BUF_CHUNK + len;
      buf = (char *) realloc (buf, alloc + 1);
    }
  memcpy (buf + ix, what, len);
  ix = newix;
  buf[ix] = '\0';
}

void
linebuf::prepend (const char *what, int len)
{
  int buflen;
  size_t newix;

  if ((newix = ix + len) >= alloc)
    {
      alloc += LINE_BUF_CHUNK + len;
      buf = (char *) realloc (buf, alloc + 1);
      buf[ix] = '\0';
    }
  if ((buflen = strlen (buf)))
    memmove (buf + len, buf, buflen + 1);
  else
    buf[newix] = '\0';
  memcpy (buf, what, len);
  ix = newix;
}

static void
make_command_line (linebuf & one_line, char **argv)
{
  for (; *argv; argv++)
    {
      char *p = NULL;
      const char *a = *argv;

      int len = strlen (a);
      if (len != 0 && !(p = strpbrk (a, " \t\n\r\"")))
        one_line.add (a, len);
      else
        {
          one_line.add ("\"", 1);
          for (; p; a = p, p = strchr (p, '"'))
            {
              one_line.add (a, ++p - a);
              if (p[-1] == '"')
                one_line.add ("\"", 1);
            }
          if (*a)
            one_line.add (a);
          one_line.add ("\"", 1);
        }
      one_line.add (" ", 1);
    }

  if (one_line.ix)
    one_line.buf[one_line.ix - 1] = '\0';
  else
    one_line.add ("", 1);
}

static BOOL WINAPI
ctrl_c (DWORD)
{
  static int tic = 1;

  note ("^C");
  if ((tic ^= 1) && !GenerateConsoleCtrlEvent (CTRL_C_EVENT, 0))
    error (0, "couldn't send CTRL-C to child, win32 error %d\n",
           GetLastError ());
  return TRUE;
}

extern "C" {
uintptr_t (*cygwin_internal) (int, ...);
WCHAR cygwin_dll_path[32768];
};

static int
load_cygwin ()
{
  static HMODULE h;

  if (cygwin_internal)
    return 1;

  if (h)
    return 0;

  if (!(h = LoadLibrary ("cygwin1.dll")))
    {
      errno = ENOENT;
      return 0;
    }
  GetModuleFileNameW (h, cygwin_dll_path, 32768);
  if (!(cygwin_internal = (uintptr_t (*) (int, ...)) GetProcAddress (h, "cygwin_internal")))
    {
      errno = ENOSYS;
      return 0;
    }
  return 1;
}

#define DEBUG_PROCESS_DETACH_ON_EXIT    0x00000001
#define DEBUG_PROCESS_ONLY_THIS_PROCESS 0x00000002

static void
attach_process (pid_t pid)
{
  child_pid = (DWORD) cygwin_internal (CW_CYGWIN_PID_TO_WINPID, pid);
  if (!child_pid)
    child_pid = pid;

  if (!DebugActiveProcess (child_pid))
    error (0, "couldn't attach to pid %d for debugging", child_pid);

  if (forkdebug)
    {
      HANDLE h = OpenProcess (PROCESS_ALL_ACCESS, FALSE, child_pid);

      if (h)
        {
          /* Try to turn off DEBUG_ONLY_THIS_PROCESS so we can follow forks */
          /* This is only supported on XP and later */
          ULONG DebugFlags = DEBUG_PROCESS_DETACH_ON_EXIT;
          NTSTATUS status = NtSetInformationProcess (h, ProcessDebugFlags, &DebugFlags, sizeof (DebugFlags));
          if (!NT_SUCCESS (status))
            warn (0, "Could not clear DEBUG_ONLY_THIS_PROCESS (%x), will not trace child processes", status);

          CloseHandle (h);
        }
    }

  return;
}

static void
create_child (char **argv)
{
  linebuf one_line;

  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  BOOL ret;
  DWORD flags;

  if (strchr (*argv, '/'))
      *argv = cygpath (*argv, NULL);
  memset (&si, 0, sizeof (si));
  si.cb = sizeof (si);

  flags = CREATE_DEFAULT_ERROR_MODE
          | (forkdebug ? DEBUG_PROCESS : DEBUG_ONLY_THIS_PROCESS);
  if (new_window)
    flags |= CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP;

  make_command_line (one_line, argv);

  SetConsoleCtrlHandler (NULL, 0);
  const char *cygwin_env = getenv ("CYGWIN");
  const char *space;
  if (cygwin_env)
    space = " ";
  else
    space = cygwin_env = "";
  char *newenv = (char *) malloc (sizeof ("CYGWIN=noglob") + strlen (space) + strlen (cygwin_env));
  sprintf (newenv, "CYGWIN=noglob%s%s", space, cygwin_env);
  _putenv (newenv);
  ret = CreateProcess (0, one_line.buf, /* command line */
                       NULL,    /* Security */
                       NULL,    /* thread */
                       TRUE,    /* inherit handles */
                       flags,   /* start flags */
                       NULL,    /* default environment */
                       NULL,    /* current directory */
                       &si, &pi);
  if (!ret)
    error (0, "error creating process %s, (error %d)", *argv,
           GetLastError ());

  CloseHandle (pi.hThread);
  CloseHandle (pi.hProcess);
  child_pid = pi.dwProcessId;
  SetConsoleCtrlHandler (ctrl_c, 1);
}

static void __stdcall
handle_output_debug_string (DWORD id, LPVOID p, FILE *ofile)
{
  //FIXME not sure we need to do anything with this
}

static BOOL
GetFileNameFromHandle (HANDLE hFile, WCHAR pszFilename[MAX_PATH+1])
{
  BOOL result = FALSE;
  ULONG len = 0;
  OBJECT_NAME_INFORMATION *ntfn = (OBJECT_NAME_INFORMATION *) alloca (65536);
  NTSTATUS status = NtQueryObject (hFile, ObjectNameInformation,
                                   ntfn, 65536, &len);
  if (NT_SUCCESS (status))
    {
      PWCHAR win32path = ntfn->Name.Buffer;
      win32path[ntfn->Name.Length / sizeof (WCHAR)] = L'\0';

      /* NtQueryObject returns a native NT path.  (Try to) convert to Win32. */
      if (drive_map)
        win32path = (PWCHAR) cygwin_internal (CW_MAP_DRIVE_MAP, drive_map,
                                              win32path);
      pszFilename[0] = L'\0';
      wcsncat (pszFilename, win32path, MAX_PATH);
      result = TRUE;
    }
  return result;
}

static DWORD
profile1 (FILE *ofile, pid_t pid)
{
  DWORD res = 0;
  DEBUG_EVENT ev;
  time_t cur_time, last_time;

  SetThreadPriority (GetCurrentThread (), THREAD_PRIORITY_HIGHEST);
  last_time = time (NULL);
  while (1)
    {
      // wait 10 secs for debug event for less system impact when no events
      BOOL debug_event = WaitForDebugEvent (&ev, 10000);
      DWORD status = DBG_CONTINUE;

      if (!debug_event)
        continue;

      // usually continue event here so child resumes while we process event
      if (ev.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
        debug_event = ContinueDebugEvent (ev.dwProcessId, ev.dwThreadId, status);

      switch (ev.dwDebugEventCode)
        {
        case CREATE_PROCESS_DEBUG_EVENT:
          if (events)
            {
              WCHAR exename[MAX_PATH+1];
              if (!GetFileNameFromHandle (ev.u.CreateProcessInfo.hFile, exename))
                wcscpy (exename, L"(unknown)");

              note ("--- Process %lu created %ls\n", ev.dwProcessId, exename);
              note ("--- Process %lu thread %lu created at %p\n",
                  ev.dwProcessId, ev.dwThreadId,
                  ev.u.CreateProcessInfo.lpStartAddress);
            }
          if (ev.u.CreateProcessInfo.hFile)
            CloseHandle (ev.u.CreateProcessInfo.hFile);
          add_child (ev.dwProcessId,
                     ev.u.CreateProcessInfo.lpBaseOfImage,
                     ev.u.CreateProcessInfo.hProcess);
          add_thread (ev.dwProcessId, ev.dwThreadId,
                      ev.u.CreateProcessInfo.hThread);
          break;

        case CREATE_THREAD_DEBUG_EVENT:
          if (events)
            note ("--- Process %lu thread %lu created at %p\n",
                  ev.dwProcessId, ev.dwThreadId,
                  ev.u.CreateThread.lpStartAddress);
          add_thread (ev.dwProcessId, ev.dwThreadId, ev.u.CreateThread.hThread);
          break;

        case LOAD_DLL_DEBUG_EVENT:
          if (events)
            {
              // lpImageName is not always populated, so find the filename for
              // hFile instead
              WCHAR dllname[MAX_PATH+1];
              if (!GetFileNameFromHandle (ev.u.LoadDll.hFile, dllname))
                wcscpy (dllname, L"(unknown)");

              note ("--- Process %lu loaded %ls at %p\n",
                    ev.dwProcessId, dllname, ev.u.LoadDll.lpBaseOfDll);
              add_span (ev.dwProcessId, dllname,
                        ev.u.LoadDll.lpBaseOfDll, ev.u.LoadDll.hFile);
            }

          if (ev.u.LoadDll.hFile)
            CloseHandle (ev.u.LoadDll.hFile);
          break;

        case UNLOAD_DLL_DEBUG_EVENT:
          if (events)
            note ("--- Process %lu unloaded DLL at %p\n",
                  ev.dwProcessId, ev.u.UnloadDll.lpBaseOfDll);
          break;
              
        case OUTPUT_DEBUG_STRING_EVENT:
          handle_output_debug_string (ev.dwProcessId,
                                      ev.u.DebugString.lpDebugStringData,
                                      ofile);
          break;
              
        case EXIT_PROCESS_DEBUG_EVENT:
          if (events)
            note ("--- Process %lu exited with status 0x%lx\n",
                  ev.dwProcessId, ev.u.ExitProcess.dwExitCode);
          res = ev.u.ExitProcess.dwExitCode;
          remove_child (ev.dwProcessId);
          break;
          
        case EXIT_THREAD_DEBUG_EVENT:
          if (events)
            note ("--- Process %lu thread %lu exited with status 0x%lx\n",
                  ev.dwProcessId, ev.dwThreadId, ev.u.ExitThread.dwExitCode);
          remove_thread (ev.dwProcessId, ev.dwThreadId);
          break;

        case EXCEPTION_DEBUG_EVENT:
          if (ev.u.Exception.ExceptionRecord.ExceptionCode
              != (DWORD) STATUS_BREAKPOINT)
            {
              status = DBG_EXCEPTION_NOT_HANDLED;
              if (ev.u.Exception.dwFirstChance)
                note ("--- Process %lu, exception %08lx at %p\n",
                      ev.dwProcessId,
                      ev.u.Exception.ExceptionRecord.ExceptionCode,
                      ev.u.Exception.ExceptionRecord.ExceptionAddress);
            } 
          debug_event = ContinueDebugEvent (ev.dwProcessId,
                                            ev.dwThreadId, status);
          break;
        }

      if (!debug_event)
        error (0, "couldn't continue debug event, windows error %d",
               GetLastError ());
      if (!numprocesses)
        break;
    }

  return res;
}

static DWORD
doprofile (FILE *ofile, pid_t pid, char **argv)
{
  if (pid)
    attach_process (pid);
  else
    create_child (argv);

  return profile1 (ofile, pid);
}

struct option longopts[] = {
  {"events", no_argument, NULL, 'e'},
  {"help", no_argument, NULL, 'h'},
  {"new-window", no_argument, NULL, 'w'},
  {"output", required_argument, NULL, 'o'},
  {"pid", required_argument, NULL, 'p'},
  {"profile-children", no_argument, NULL, 'f'},
  {"quiet", no_argument, NULL, 'q'},
  {"sample-rate", required_argument, NULL, 's'},
  {"version", no_argument, NULL, 'V'},
  {NULL, 0, NULL, 0}
};

static const char *const opts = "+ehfo:p:qs:Vw";

static void
print_version ()
{
  printf ("cygmon (cygwin) %d.%d.%d\n"
          "System Profiler\n"
          "Copyright (C) 2016 Red Hat, Inc.\n"
          "This is free software; see the source for copying conditions.  There is NO\n"
          "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
          CYGWIN_VERSION_DLL_MAJOR / 1000,
          CYGWIN_VERSION_DLL_MAJOR % 1000,
          CYGWIN_VERSION_DLL_MINOR );
}

int
main2 (int argc, char **argv)
{
  FILE *ofile = NULL;
  pid_t pid = 0;
  int opt;
  int sawquiet = -1;
  DWORD ret = 0;

  if (load_cygwin ())
    {
      char **av = (char **) cygwin_internal (CW_ARGV);
      if (av && (uintptr_t) av != (uintptr_t) -1)
        for (argc = 0, argv = av; *av; av++)
          argc++;
    }

  if (!(pgm = strrchr (*argv, '\\')) && !(pgm = strrchr (*argv, '/')))
    pgm = *argv;
  else
    pgm++;

  while ((opt = getopt_long (argc, argv, opts, longopts, NULL)) != EOF)
    switch (opt)
      {
      case 'e':
        events ^= 1;
        break;
      case 'f':
        forkdebug ^= 1;
        break;
      case 'h':
        // Print help and exit
        usage (stdout);
        break;
      case 'o':
        if ((ofile = fopen (cygpath (optarg, NULL), "wb")) == NULL)
          error (1, "can't open %s", optarg);
#ifdef F_SETFD
        (void) fcntl (fileno (ofile), F_SETFD, 0);
#endif
        break;
      case 'p':
        pid = strtoul (optarg, NULL, 10);
        break;
      case 'q':
        if (sawquiet < 0)
          sawquiet = 1;
        else
          sawquiet ^= 1;
        break;
      case 's':
        samplerate = strtoul (optarg, NULL, 10);
        if (samplerate < 1 || samplerate > 1000)
          error (0, "sample rate must be between 1 and 1000 inclusive");
        break;
      case 'V':
        // Print version info and exit
        print_version ();
        return 0;
      case 'w':
        new_window ^= 1;
        break;
      default:
        note ("Try `%s --help' for more information.\n", pgm);
        exit (1);
      }
        
  if (pid && argv[optind])
    error (0, "cannot provide both a command line and a process id");

  if (!pid && !argv[optind])
    error (0, "must provide either a command line or a process id");

  if (!pid)
    quiet = sawquiet < 0 || !sawquiet;
  else if (sawquiet < 0)
    quiet = 0;
  else
    quiet = sawquiet;

  if (!ofile)
    ofile = stdout;

  drive_map = (void *) cygwin_internal (CW_ALLOC_DRIVE_MAP);
  ret = doprofile (ofile, pid, argv + optind);
  if (drive_map)
    cygwin_internal (CW_FREE_DRIVE_MAP, drive_map);

  if (ofile && ofile != stdout)
    fclose (ofile);
  ExitProcess (ret);
}

int
main (int argc, char **argv)
{
  /* Make sure to have room for the _cygtls area *and* to initialize it.
   * This is required to make sure cygwin_internal calls into Cygwin work
   * reliably.  This problem has been noticed under AllocationPreference
   * registry setting to 0x100000 (TOP_DOWN).
   */
  char buf[CYGTLS_PADSIZE];

  memset (buf, 0, sizeof (buf));
  exit (main2 (argc, argv));
}
