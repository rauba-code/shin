# SHIN :: The SHell INspector

Spawns a shell in a controlled state using `ptrace` and monitors its activity while feeding the input.

This is supposed to be a debugging tool, an enhanced version of `sh -x`. SHIN is designed to allow user to trace, modify, or skip commands provided a batch script or a piped output. Besides, the application may be useful for debugging all types of general-purpose interpreted programming languages (e.g. LISP, JavaScript, Python, Lua, etc.).

The current state of the application is a mere proof of concept, there is nothing to do with it. The design may drastically change in newer versions. Therefore, it is not recommended to use the software in production or even for personal use.

The application requires the Linux kernel version 5.3 or above. It is architecture-independent. Support of the older kernels and the other UNIX-family operating systems (BSD, Redox, etc. but not Solaris) is feasible, and is in the roadmap.