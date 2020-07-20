WerTweak
========

WerTweak improves the crash reports of Windows Error Reporting (WER) on Windows 10. WER is the component in Windows that is responsible for handling application crashes. Starting with Windows 10, WER has undergone some changes, most notably:

- When a process has crashed, WER now handles the crash by default in a completely silent way. The crashed process is simply terminated immediately without letting the user know what went wrong. This behavior can be disabled if you set WER's [`DontShowUI`](https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings#DontShowUI) setting to `0`, either via Group Policy or manually in the registry.

- Even with `DontShowUI` set to `0`, WER will never show crash reports for some specific processes. For example, background processes without any user interface still crash silently. Another example is the `explorer.exe` process, which is always restarted automatically by WER when it has crashed.

- When WER notifies the user of a crash, it does so using a dialog containing only the name of the crashed process. This dialog lacks more detailed information, such as the exact type of crash, the faulting module name, the exception code etc.

While these changes might seem acceptable for average Windows users, they are usually not wanted by power users and software developers, who will want to be notified instantly when a process crashes, with a crash report that contains detailed information.

That is where WerTweak comes in. WerTweak is a system tool that hooks itself into WER and modifies its behavior as follows:

- WerTweak forces WER to notify the user of *all* crashes, even if they occur in invisible background processes. Furthermore, it unsets certain internal flags set by WER in case a 'special' process (such as `explorer.exe`) crashes, so that these crashes are also reported to the user.

- With WerTweak installed, WER displays the same old-style crash reporting dialog as in previous versions of Windows, meaning that detailed crash information is shown again.
