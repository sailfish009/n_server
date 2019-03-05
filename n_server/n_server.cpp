// n_server.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include "define.h"


// using external libraries nanomsg 
///////////////////////////////////////////////////
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "../ext/lib/nanomsg.lib")


const int COMMAND_LENGTH = 2;
const std::string RESULT_OK = "OK";
const std::string RESULT_NG = "NG";

///////////////////////////////////////////////////

/*  MAXJOBS is a limit on the on the number of outstanding requests we
    can queue.  We will not accept new inbound jobs if we have more than
    this queued.  The reason for this limit is to prevent a bad client
    from consuming all server resources with new job requests. */

#define MAXJOBS 100

/*  The server keeps a list of work items, sorted by expiration time,
    so that we can use this to set the timeout to the correct value for
    use in poll.  */

struct work
{
  struct work *next;
  struct nn_msghdr request;
  uint64_t expire;
  void *control;
};

/*  Return the UNIX time in milliseconds.  You'll need a working
    gettimeofday(), so this won't work on Windows.  */
#include <chrono>
uint64_t milliseconds(void)
{
#ifdef _WIN32
  return std::chrono::duration_cast<std::chrono::milliseconds>
    (std::chrono::steady_clock::now().time_since_epoch()).count();
#else
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (((uint64_t)tv.tv_sec * 1000) + ((uint64_t)tv.tv_usec / 1000));
#endif
}


size_t strerrorlen_s(errno_t errnum)
{
#ifndef ESNULLP
#define ESNULLP         ( 400 )       /* null ptr */
#endif

#ifndef ESLEWRNG
#define ESLEWRNG        ( 410 )       /* wrong size */
#endif

#ifndef ESLAST
#define ESLAST ESLEWRNG
#endif

  static const int len_errmsgs_s[] = 
  {
    sizeof "null ptr",                /* ESNULLP */
    sizeof "length is zero",          /* ESZEROL */
    sizeof "length is below min",     /* ESLEMIN */
    sizeof "length exceeds RSIZE_MAX",/* ESLEMAX */
    sizeof "overlap undefined",       /* ESOVRLP */
    sizeof "empty string",            /* ESEMPTY */
    sizeof "not enough space",        /* ESNOSPC */
    sizeof "unterminated string",     /* ESUNTERM */
    sizeof "no difference",           /* ESNODIFF */
    sizeof "not found",               /* ESNOTFND */
    sizeof "wrong size",              /* ESLEWRNG */
  };

#pragma warning(disable : 4996)

  if (errnum >= ESNULLP && errnum <= ESLAST) 
  {
    return len_errmsgs_s[errnum - ESNULLP] - 1;
  }
  else 
  {
    const char *buf = strerror(errnum);
    return buf ? strlen(buf) : 0;
  }
}

///////////////////////////////////////////////////


/*  The server runs forever. */
int server(const char *url)
{
  struct work *worklist = NULL;
  int npending = 0;

  /*  Create the socket. */
  int fd = nn_socket(AF_SP_RAW, NN_REP);
  if (fd < 0) 
  {
    fprintf(stderr, "nn_socket: %s\n", nn_strerror(nn_errno()));
    return (-1);
  }

  /*  Bind to the URL.  This will bind to the address and listen
      synchronously; new clients will be accepted asynchronously
      without further action from the calling program. */

  if (nn_bind(fd, url) < 0) 
  {
    fprintf(stderr, "nn_bind: %s\n", nn_strerror(nn_errno()));
    nn_close(fd);
    return (-1);
  }

  /*  Main processing loop. */

  uint32_t g_timer = 323;
  uint8_t buffer[256] = { 0 };

  for (;;) 
  {
    uint32_t timer;
    int rcv;
    int timeout;
    uint64_t now;
    struct work *work, **srch;
    uint8_t *body;
    void *control;
    struct nn_iovec iov;
    struct nn_msghdr hdr;
    struct nn_pollfd pfd[1];

    /*  Figure out if any work requests are finished, and can be
        responded to. */

    timeout = -1;
    while ((work = worklist) != NULL) 
    {
      now = milliseconds();
      if (work->expire > now) 
      {
        timeout = (int)(work->expire - now);
        break;
      }
      worklist = work->next;
      npending--;
      rcv = nn_sendmsg(fd, &work->request, NN_DONTWAIT);
      if (rcv < 0) 
      {
        fprintf(stderr, "nn_sendmsg: %s\n", nn_strerror(nn_errno()));
        nn_freemsg(work->request.msg_control);
      }
      free(work);
    }

    /*  This check ensures that we don't allow more than a set limit
        of concurrent jobs to be queued.  This protects us from resource
        exhaustion by malicious or defective clients. */

    if (npending >= MAXJOBS) 
    {
      nn_poll(pfd, 0, timeout);
      continue;
    }

    pfd[0].fd = fd;
    pfd[0].events = NN_POLLIN;
    pfd[0].revents = 0;
    nn_poll(pfd, 1, timeout);

    if ((pfd[0].revents & NN_POLLIN) == 0) 
    {
      continue;
    }

    /*  So there should be a message waiting for us to receive.
        We handle it by parsing it, creating a work request for it,
        and adding the work request to the worklist. */

    memset(&hdr, 0, sizeof(hdr));
    control = NULL;
    iov.iov_base = &body;
    iov.iov_len = NN_MSG;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = &control;
    hdr.msg_controllen = NN_MSG;

    rcv = nn_recvmsg(fd, &hdr, 0);
    if (rcv < 0) 
    {
      /*  Any error here is unexpected. */
      fprintf(stderr, "nn_recv: %s\n", nn_strerror(nn_errno()));
      break;
    }

    // if (rcv != sizeof(uint32_t)) 
    if (rcv != BUFFER_SIZE) 
    {
      fprintf(stderr, "nn_recv: wanted %d, but got %d\n", (int) sizeof(uint32_t), rcv);
      nn_freemsg(body);
      nn_freemsg(control);
      continue;
    }

    printf("rcv: %d\n", rcv);

    // memcpy(&timer, body, sizeof(timer));
    memset(buffer, 0, 256);
    memcpy(buffer, body, rcv);
    nn_freemsg(body);

    work = (struct work*)malloc(sizeof(*work));
    if (work == NULL) 
    {
      // fprintf(stderr, "malloc: %s\n", strerror(errno));
      size_t errmsglen = strerrorlen_s(errno) + 1;
      char errmsg[32] = { 0 };
      strerror_s(errmsg, errmsglen, errno);
      printf("Fatal error -- malloc: %s\n", errmsg);
      /*  Fatal error -- other programs can try to handle it better. */
      break;
    }
    memset(work, 0, sizeof(*work));

    work->expire = milliseconds(); // +ntohl(timer);
    // work->expire = milliseconds() + ntohl(g_timer);
    work->control = control;

#if true
    struct nn_iovec siov;
    siov.iov_base = &buffer;
    siov.iov_len = 256;
    work->request.msg_iov = &siov;
    work->request.msg_iovlen = 1;  /*  No payload data to send. */
#else
    work->request.msg_iovlen = 0;  /*  No payload data to send. */
    work->request.msg_iov = NULL;
#endif

    work->request.msg_control = &work->control;
    work->request.msg_controllen = NN_MSG;

    /*  Insert the work request into the list in order. */
    srch = &worklist;
    for (;;) 
    {
      if ((*srch == NULL) || ((*srch)->expire > work->expire)) 
      {
        work->next = *srch;
        *srch = work;
        npending++;
        break;
      }
      srch = &((*srch)->next);
    }
  }

  /*  This may wind up orphaning requests in the queue.   We are going
      to exit with an error anyway, so don't worry about it. */

  nn_close(fd);
  return (-1);
}


int main()
{
  // std::cout << "Hello World!\n"; 
  server("tcp://127.0.0.1:5555");
  return 0;
}

