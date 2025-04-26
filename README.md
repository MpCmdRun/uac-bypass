# UAC-Bypass-Dropper

🚀 A C# clone of a native UAC bypass method using `IFileOperation` with elevated COM interface abuse and DLL hijacking of `ATL.dll` inside `Wbem` directory.

---

## Features
- 🛡️ Masquerades as `explorer.exe`
- 📦 Patches entrypoint of DLL with minimal shellcode
- 🪄 Drops and plants `ATL.dll` into `wbem\`
- 🔥 Launches `WmiMgmt.msc` to trigger payload
- 🧹 Self-cleans dropped DLL afterwards

---

## ⚠️ Warning

This code is intended for **educational** and **research** purposes only.

---

## 🛠️ Build

- Visual Studio 2022+  
- .NET Framework 4.8  
- **Release** x64 mode highly recommended.

---

## 📚 References
- [LOLBAS Project](https://lolbas-project.github.io)
- [Advanced UAC Bypass Techniques](https://www.mdsec.co.uk/2020/05/uac-bypass-using-iFileOperation)

---

## 👤 Credits
- [0x0000000A](https://github.com/MpCmdRun)
- [clout](https://t.me/omenist)

---

## 📜 License

MIT License (see [LICENSE](LICENSE))
