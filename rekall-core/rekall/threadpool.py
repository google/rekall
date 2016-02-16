# Rekall Memory Forensics
#
# Copyright 2013 Google Inc. All Rights Reserved.
#
# Authors:
# Michael Cohen <scudette@gmail.com>
# Copyright (c) 2012
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
import logging
import threading
import traceback
import Queue


# Simple threadpool implementation - we just run all tests in the pool for
# maximum concurrency.
class Worker(threading.Thread):
    """A Threadpool worker.

    Reads jobs from the queue and runs them. Quits when a None job is received
    on the queue.
    """
    def __init__(self, queue):
        super(Worker, self).__init__()
        self.queue = queue
        self.daemon = True

        # Start the thread immediately.
        self.start()

    def run(self):
        while True:
            # Get a callable from the queue.
            task, args, kwargs = self.queue.get()

            try:
                # Stop the worker by sending it a task of None.
                if task is None:
                    break

                on_error = kwargs.pop("on_error", lambda x: None)

                task(*args, **kwargs)
            except Exception as e:
                print e
                logging.error("Worker raised %s", e)
                traceback.print_exc()
                on_error(e)

            finally:
                self.queue.task_done()


class ThreadPool(object):
    lock = threading.Lock()

    def __init__(self, number_of_threads):
        self.number_of_threads = number_of_threads
        self.queue = Queue.Queue(2 * number_of_threads)
        self.workers = [Worker(self.queue) for _ in range(number_of_threads)]

    def Stop(self):
        """Stop all the threads when they are ready."""
        self.queue.join()

        # Send all workers the stop message.
        for worker in self.workers:
            self.AddTask(None)

        for worker in self.workers:
            worker.join()

    def AddTask(self, task, args=None, kwargs=None, on_error=None):
        if kwargs is None:
            kwargs = {}
        kwargs["on_error"] = on_error
        self.queue.put((task, args or [], kwargs))
