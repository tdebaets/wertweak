WerTweak
========

WerTweak improves the crash reports of Windows Error Reporting (WER) on Windows 10. WER is the component in Windows that is responsible for handling application crashes. Starting with Windows 10, WER has undergone some changes, most notably:

- When a process has crashed, WER now handles the crash by default in a completely silent way. The crashed process is simply terminated immediately without letting the user know what went wrong. This behavior can be disabled if you set WER's [`DontShowUI`](https://docs.microsoft.com/en-us/windows/win32/wer/wer-settings#DontShowUI) setting to `0`, either via Group Policy or manually in the registry.

- Even with `DontShowUI` set to `0`, WER will never show crash reports for some specific processes. For example, background processes without any user interface still crash silently. Another example is the `explorer.exe` process, which is always restarted automatically by WER when it has crashed.

- When WER notifies the user of a crash, it does so using a dialog containing only the name of the crashed process. This dialog lacks more detailed information, such as the exact type of crash, the faulting module name, the exception code etc. ([example](Images/crashreport-before.png?raw=true)).

While these changes might seem acceptable for average Windows users, they are usually not wanted by power users and software developers, who will want to be notified instantly when a process crashes, with a crash report that contains detailed information.

That is where WerTweak comes in. WerTweak is a system tool that hooks itself into WER and modifies its behavior as follows:

- WerTweak forces WER to notify the user of *all* crashes, even if they occur in invisible background processes. Furthermore, it unsets certain internal flags set by WER in case a 'special' process (such as `explorer.exe`) crashes, so that these crashes are also reported to the user.

- With WerTweak installed, WER displays the same old-style crash reporting dialog as in previous versions of Windows, meaning that detailed crash information is shown again ([example](Images/crashreport-after.png?raw=true)).

Obtaining the source code
-------------------------

First make sure that you have a recent version of the [Git client](https://git-scm.com/) (`git`) installed. Then open a Windows command prompt window (note: Git Bash isn't supported). In the command prompt, run these commands:
```
> git clone https://github.com/tdebaets/wertweak.git wertweak
> cd wertweak
```

Finally, run the `postclone.bat` script. This will take care of further setting up the repository, installing Git hooks, creating output directories etc.:
```
> postclone.bat
```

To keep your repository up-to-date, run the `update.bat` script. This script essentially runs a `git pull` but also performs some basic checks before pulling. It also runs a `git submodule update` after the pull to update the `common` submodule as well.

If you want to contribute to this project, don't clone its main repository, but create your own fork first and clone that fork instead. Then commit/push your work on a topic branch and submit a pull request. For details, see the [generic instructions for contributing to projects](https://github.com/tdebaets/common/blob/master/CONTRIBUTING.md).

Building
--------

WerTweak has been written in C++ using [Microsoft Visual Studio Community 2019](https://visualstudio.microsoft.com/vs/). This means that in order to build this project, you'll need to have Visual Studio 2019 installed. Other releases of Visual Studio may also work but are unsupported.

Installing
----------

After having built WerTweak, you can manually install it by making an addition to the registry (there's no automatic installer script yet). The exact instructions vary slightly depending on whether you’re running 64-bit or 32-bit Windows:

- **64-bit Windows**

  Navigate to either the `Output\x64\Release` or `Output\x64\Debug` subdirectory of the repository, depending on which build configuration you want to use. Make sure that these 3 files exist in this subdirectory: `WerTweak.dll`, `WerTweak64.dll` and `WerTweak64.exe`. Then add this entry to the registry, replacing `<x64 output directory>` in Data with the full path to the directory that you're currently in:
  
  **`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WerFault.exe`**
  
  Name: `Debugger`
  
  Type: `REG_SZ`
  
  Data: `<x64 output directory>\WerTweak64.exe`

- **32-bit Windows**

  Navigate to either the `Output\Release` or `Output\Debug` subdirectory of the repository, depending on which build configuration you want to use. Make sure that these 2 files exist in this subdirectory: `WerTweak.dll` and `WerTweak.exe`. Then add this entry to the registry, replacing `<x86 output directory>` in Data with the full path to the directory that you're currently in:
  
  **`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WerFault.exe`**
  
  Name: `Debugger`
  
  Type: `REG_SZ`
  
  Data: `<x86 output directory>\WerTweak.exe`

License
-------

WerTweak is Copyright © 2020 Tim De Baets. It is licensed under the Mozilla Public License version 2.0, see [`LICENSE`](LICENSE) for details.
