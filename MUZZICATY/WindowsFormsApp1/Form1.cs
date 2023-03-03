using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Siticone.UI.WinForms;

namespace WindowsFormsApp1
{
	// Token: 0x02000004 RID: 4
	public partial class Form1 : Form
	{
		// Token: 0x06000008 RID: 8 RVA: 0x000020FC File Offset: 0x000002FC
		public Form1()
		{
			this.InitializeComponent();
		}

		// Token: 0x06000009 RID: 9 RVA: 0x0000217E File Offset: 0x0000037E
		private void Form1_Load(object sender, EventArgs e)
		{
			Directory.CreateDirectory("moded");
			Directory.CreateDirectory("orginal");
		}

		// Token: 0x0600000A RID: 10 RVA: 0x00002198 File Offset: 0x00000398
		public static void RunCMD(string command, bool ShowWindow = false, bool WaitForProcessComplete = true, bool permanent = false)
		{
			Process process = new Process();
			ProcessStartInfo processStartInfo = new ProcessStartInfo();
			processStartInfo.Arguments = " " + ((ShowWindow && permanent) ? "/K" : "/C") + " " + command;
			processStartInfo.FileName = "cmd.exe";
			processStartInfo.CreateNoWindow = !ShowWindow;
			if (ShowWindow)
			{
				processStartInfo.WindowStyle = ProcessWindowStyle.Normal;
			}
			else
			{
				processStartInfo.WindowStyle = ProcessWindowStyle.Hidden;
			}
			process.StartInfo = processStartInfo;
			process.Start();
			if (WaitForProcessComplete)
			{
				while (!process.HasExited)
				{
				}
			}
		}

		// Token: 0x17000004 RID: 4
		// (get) Token: 0x0600000B RID: 11 RVA: 0x00002238 File Offset: 0x00000438
		// (set) Token: 0x0600000C RID: 12 RVA: 0x00002250 File Offset: 0x00000450
		public bool Is64Bit
		{
			get
			{
				return this._is64Bit;
			}
			private set
			{
				this._is64Bit = value;
			}
		}

		// Token: 0x0600000D RID: 13
		[DllImport("KERNEL32.DLL")]
		public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint processid);

		// Token: 0x0600000E RID: 14
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

		// Token: 0x0600000F RID: 15
		[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
		public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out Form1.MEMORY_BASIC_INFORMATION32 lpBuffer, UIntPtr dwLength);

		// Token: 0x06000010 RID: 16
		[DllImport("kernel32.dll", EntryPoint = "VirtualQueryEx")]
		public static extern UIntPtr Native_VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out Form1.MEMORY_BASIC_INFORMATION64 lpBuffer, UIntPtr dwLength);

		// Token: 0x06000011 RID: 17
		[DllImport("kernel32.dll")]
		private static extern uint GetLastError();

		// Token: 0x06000012 RID: 18 RVA: 0x0000225C File Offset: 0x0000045C
		public UIntPtr VirtualQueryEx(IntPtr hProcess, UIntPtr lpAddress, out Form1.MEMORY_BASIC_INFORMATION lpBuffer)
		{
			bool flag = this.Is64Bit || IntPtr.Size == 8;
			UIntPtr result;
			if (flag)
			{
				Form1.MEMORY_BASIC_INFORMATION64 memory_BASIC_INFORMATION = default(Form1.MEMORY_BASIC_INFORMATION64);
				UIntPtr uintPtr = Form1.Native_VirtualQueryEx(hProcess, lpAddress, out memory_BASIC_INFORMATION, new UIntPtr((uint)Marshal.SizeOf(memory_BASIC_INFORMATION)));
				lpBuffer.BaseAddress = memory_BASIC_INFORMATION.BaseAddress;
				lpBuffer.AllocationBase = memory_BASIC_INFORMATION.AllocationBase;
				lpBuffer.AllocationProtect = memory_BASIC_INFORMATION.AllocationProtect;
				lpBuffer.RegionSize = (long)memory_BASIC_INFORMATION.RegionSize;
				lpBuffer.State = memory_BASIC_INFORMATION.State;
				lpBuffer.Protect = memory_BASIC_INFORMATION.Protect;
				lpBuffer.Type = memory_BASIC_INFORMATION.Type;
				result = uintPtr;
			}
			else
			{
				Form1.MEMORY_BASIC_INFORMATION32 memory_BASIC_INFORMATION2 = default(Form1.MEMORY_BASIC_INFORMATION32);
				UIntPtr uintPtr = Form1.Native_VirtualQueryEx(hProcess, lpAddress, out memory_BASIC_INFORMATION2, new UIntPtr((uint)Marshal.SizeOf(memory_BASIC_INFORMATION2)));
				lpBuffer.BaseAddress = memory_BASIC_INFORMATION2.BaseAddress;
				lpBuffer.AllocationBase = memory_BASIC_INFORMATION2.AllocationBase;
				lpBuffer.AllocationProtect = memory_BASIC_INFORMATION2.AllocationProtect;
				lpBuffer.RegionSize = (long)((ulong)memory_BASIC_INFORMATION2.RegionSize);
				lpBuffer.State = memory_BASIC_INFORMATION2.State;
				lpBuffer.Protect = memory_BASIC_INFORMATION2.Protect;
				lpBuffer.Type = memory_BASIC_INFORMATION2.Type;
				result = uintPtr;
			}
			return result;
		}

		// Token: 0x06000013 RID: 19
		[DllImport("kernel32.dll")]
		private static extern void GetSystemInfo(out Form1.SYSTEM_INFO lpSystemInfo);

		// Token: 0x06000014 RID: 20
		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenThread(Form1.ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

		// Token: 0x06000015 RID: 21
		[DllImport("kernel32.dll")]
		private static extern uint SuspendThread(IntPtr hThread);

		// Token: 0x06000016 RID: 22
		[DllImport("kernel32.dll")]
		private static extern int ResumeThread(IntPtr hThread);

		// Token: 0x06000017 RID: 23
		[DllImport("dbghelp.dll")]
		private static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, Form1.MINIDUMP_TYPE DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallackParam);

		// Token: 0x06000018 RID: 24
		[DllImport("user32.dll", SetLastError = true)]
		private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

		// Token: 0x06000019 RID: 25
		[DllImport("user32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr w, IntPtr l);

		// Token: 0x0600001A RID: 26
		[DllImport("kernel32.dll")]
		private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, string lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

		// Token: 0x0600001B RID: 27
		[DllImport("kernel32.dll")]
		private static extern int GetProcessId(IntPtr handle);

		// Token: 0x0600001C RID: 28
		[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
		private static extern uint GetPrivateProfileString(string lpAppName, string lpKeyName, string lpDefault, StringBuilder lpReturnedString, uint nSize, string lpFileName);

		// Token: 0x0600001D RID: 29
		[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
		private static extern bool VirtualFreeEx(IntPtr hProcess, UIntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

		// Token: 0x0600001E RID: 30
		[DllImport("kernel32.dll")]
		private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesRead);

		// Token: 0x0600001F RID: 31
		[DllImport("kernel32.dll")]
		private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

		// Token: 0x06000020 RID: 32
		[DllImport("kernel32.dll")]
		private static extern bool ReadProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, [Out] IntPtr lpBuffer, UIntPtr nSize, out ulong lpNumberOfBytesRead);

		// Token: 0x06000021 RID: 33
		[DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
		private static extern UIntPtr VirtualAllocEx(IntPtr hProcess, UIntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		// Token: 0x06000022 RID: 34
		[DllImport("kernel32.dll")]
		private static extern bool VirtualProtectEx(IntPtr hProcess, UIntPtr lpAddress, IntPtr dwSize, Form1.MemoryProtection flNewProtect, out Form1.MemoryProtection lpflOldProtect);

		// Token: 0x06000023 RID: 35
		[DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
		public static extern UIntPtr GetProcAddress(IntPtr hModule, string procName);

		// Token: 0x06000024 RID: 36
		[DllImport("kernel32.dll", EntryPoint = "CloseHandle")]
		private static extern bool _CloseHandle(IntPtr hObject);

		// Token: 0x06000025 RID: 37
		[DllImport("kernel32.dll")]
		public static extern int CloseHandle(IntPtr hObject);

		// Token: 0x06000026 RID: 38
		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr GetModuleHandle(string lpModuleName);

		// Token: 0x06000027 RID: 39
		[DllImport("kernel32", ExactSpelling = true, SetLastError = true)]
		internal static extern int WaitForSingleObject(IntPtr handle, int milliseconds);

		// Token: 0x06000028 RID: 40
		[DllImport("kernel32.dll")]
		private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, IntPtr lpNumberOfBytesWritten);

		// Token: 0x06000029 RID: 41
		[DllImport("kernel32.dll")]
		private static extern bool WriteProcessMemory(IntPtr hProcess, UIntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

		// Token: 0x0600002A RID: 42
		[DllImport("kernel32")]
		public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, UIntPtr lpStartAddress, UIntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

		// Token: 0x0600002B RID: 43
		[DllImport("kernel32")]
		public static extern bool IsWow64Process(IntPtr hProcess, out bool lpSystemInfo);

		// Token: 0x0600002C RID: 44
		[DllImport("user32.dll")]
		private static extern bool SetForegroundWindow(IntPtr hWnd);

		// Token: 0x0600002D RID: 45
		[DllImport("KERNEL32.DLL")]
		public static extern int Process32First(IntPtr handle, ref Form1.ProcessEntry32 pe);

		// Token: 0x0600002E RID: 46
		[DllImport("KERNEL32.DLL")]
		public static extern int Process32Next(IntPtr handle, ref Form1.ProcessEntry32 pe);

		// Token: 0x0600002F RID: 47
		[DllImport("ntdll.dll", SetLastError = true)]
		private static extern Form1.NtStatus NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToRead, ref uint NumberOfBytesRead);

		// Token: 0x06000030 RID: 48
		[DllImport("ntdll.dll", SetLastError = true)]
		private static extern Form1.NtStatus NtOpenProcess(ref IntPtr ProcessHandle, uint AccessMask, ref Form1.OBJECT_ATTRIBUTES ObjectAttributes, ref Form1.CLIENT_ID ClientId);

		// Token: 0x06000031 RID: 49
		[DllImport("ntdll.dll", SetLastError = true)]
		private static extern Form1.NtStatus NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, ref uint NumberOfBytesWritten);

		// Token: 0x06000032 RID: 50 RVA: 0x0000237C File Offset: 0x0000057C
		private bool IsDigitsOnly(string str)
		{
			foreach (char c in str)
			{
				bool flag = c < '0' || c > '9';
				if (flag)
				{
					return false;
				}
			}
			return true;
		}

		// Token: 0x06000033 RID: 51 RVA: 0x000023C8 File Offset: 0x000005C8
		public void FreezeValue(string address, string type, string value, string file = "")
		{
			CancellationTokenSource cts = new CancellationTokenSource();
			bool flag = this.FreezeTokenSrcs.ContainsKey(address);
			if (flag)
			{
				Debug.WriteLine("Changing Freezing Address " + address + " Value " + value);
				try
				{
					this.FreezeTokenSrcs[address].Cancel();
					this.FreezeTokenSrcs.Remove(address);
				}
				catch
				{
					Debug.WriteLine("ERROR: Avoided a crash. Address " + address + " was not frozen.");
				}
			}
			else
			{
				Debug.WriteLine("Adding Freezing Address " + address + " Value " + value);
			}
			this.FreezeTokenSrcs.Add(address, cts);
			Task.Factory.StartNew(delegate()
			{
				while (!cts.Token.IsCancellationRequested)
				{
					this.WriteMemory(address, type, value, file, null);
					Thread.Sleep(25);
				}
			}, cts.Token);
		}

		// Token: 0x06000034 RID: 52 RVA: 0x00002500 File Offset: 0x00000700
		public void UnfreezeValue(string address)
		{
			Debug.WriteLine("Un-Freezing Address " + address);
			try
			{
				this.FreezeTokenSrcs[address].Cancel();
				this.FreezeTokenSrcs.Remove(address);
			}
			catch
			{
				Debug.WriteLine("ERROR: Address " + address + " was not frozen.");
			}
		}

		// Token: 0x06000035 RID: 53 RVA: 0x00002570 File Offset: 0x00000770
		public bool OpenProcess(int pid)
		{
			bool flag = pid <= 0;
			bool result;
			if (flag)
			{
				result = false;
			}
			else
			{
				bool flag2 = this.theProc != null && this.theProc.Id == pid;
				if (flag2)
				{
					result = true;
				}
				else
				{
					try
					{
						this.theProc = Process.GetProcessById(pid);
						bool flag3 = this.theProc != null && !this.theProc.Responding;
						if (flag3)
						{
							result = false;
						}
						else
						{
							Form1.CloseHandle(this.pHandle);
							this.pHandle = IntPtr.Zero;
							this.pHandle = Form1.OpenProcess(2035711U, false, pid);
							result = true;
						}
					}
					catch
					{
						result = false;
					}
				}
			}
			return result;
		}

		// Token: 0x06000036 RID: 54 RVA: 0x00002628 File Offset: 0x00000828
		public bool OpenProcess(string proc)
		{
			return this.OpenProcess(this.GetProcIdFromName(proc));
		}

		// Token: 0x06000037 RID: 55 RVA: 0x00002648 File Offset: 0x00000848
		public bool IsAdmin()
		{
			return true;
		}

		// Token: 0x06000038 RID: 56 RVA: 0x0000265C File Offset: 0x0000085C
		public void GetModules()
		{
			bool flag = this.theProc == null;
			if (!flag)
			{
				this.modules.Clear();
				foreach (object obj in this.theProc.Modules)
				{
					ProcessModule processModule = (ProcessModule)obj;
					bool flag2 = !string.IsNullOrEmpty(processModule.ModuleName) && !this.modules.ContainsKey(processModule.ModuleName);
					if (flag2)
					{
						this.modules.Add(processModule.ModuleName, processModule.BaseAddress);
					}
				}
			}
		}

		// Token: 0x06000039 RID: 57 RVA: 0x0000271C File Offset: 0x0000091C
		public void SetFocus()
		{
			Form1.SetForegroundWindow(this.theProc.MainWindowHandle);
		}

		// Token: 0x0600003A RID: 58 RVA: 0x00002730 File Offset: 0x00000930
		public int GetProcIdFromName(string name)
		{
			Process[] processes = Process.GetProcesses();
			bool flag = name.ToLower().Contains(".exe");
			if (flag)
			{
				name = name.Replace(".exe", "");
			}
			bool flag2 = name.ToLower().Contains(".bin");
			if (flag2)
			{
				name = name.Replace(".bin", "");
			}
			Process[] array = processes;
			foreach (Process process in array)
			{
				bool flag3 = process.ProcessName.Equals(name, StringComparison.CurrentCultureIgnoreCase);
				if (flag3)
				{
					return process.Id;
				}
			}
			return 0;
		}

		// Token: 0x0600003B RID: 59 RVA: 0x000027E0 File Offset: 0x000009E0
		public string LoadCode(string name, string file)
		{
			StringBuilder stringBuilder = new StringBuilder(1024);
			bool flag = file != "";
			if (flag)
			{
				uint privateProfileString = Form1.GetPrivateProfileString("codes", name, "", stringBuilder, (uint)stringBuilder.Capacity, file);
			}
			else
			{
				stringBuilder.Append(name);
			}
			return stringBuilder.ToString();
		}

		// Token: 0x0600003C RID: 60 RVA: 0x0000283C File Offset: 0x00000A3C
		private int LoadIntCode(string name, string path)
		{
			int result;
			try
			{
				int num = Convert.ToInt32(this.LoadCode(name, path), 16);
				bool flag = num >= 0;
				if (flag)
				{
					result = num;
				}
				else
				{
					result = 0;
				}
			}
			catch
			{
				Debug.WriteLine("ERROR: LoadIntCode function crashed!");
				result = 0;
			}
			return result;
		}

		// Token: 0x0600003D RID: 61 RVA: 0x00002894 File Offset: 0x00000A94
		public string CutString(string str)
		{
			StringBuilder stringBuilder = new StringBuilder();
			foreach (char c in str)
			{
				bool flag = c >= ' ' && c <= '~';
				if (!flag)
				{
					break;
				}
				stringBuilder.Append(c);
			}
			return stringBuilder.ToString();
		}

		// Token: 0x0600003E RID: 62 RVA: 0x000028F4 File Offset: 0x00000AF4
		public string SanitizeString(string str)
		{
			StringBuilder stringBuilder = new StringBuilder();
			foreach (char c in str)
			{
				bool flag = c >= ' ' && c <= '~';
				if (flag)
				{
					stringBuilder.Append(c);
				}
			}
			return stringBuilder.ToString();
		}

		// Token: 0x0600003F RID: 63 RVA: 0x00002954 File Offset: 0x00000B54
		public bool ChangeProtection(string code, Form1.MemoryProtection newProtection, out Form1.MemoryProtection oldProtection, string file = "")
		{
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = code2 == UIntPtr.Zero || this.pHandle == IntPtr.Zero;
			bool result;
			if (flag)
			{
				oldProtection = (Form1.MemoryProtection)0U;
				result = false;
			}
			else
			{
				result = Form1.VirtualProtectEx(this.pHandle, code2, (IntPtr)(this.Is64Bit ? 8 : 4), newProtection, out oldProtection);
			}
			return result;
		}

		// Token: 0x06000040 RID: 64 RVA: 0x000029BC File Offset: 0x00000BBC
		private byte[] ReadBytes(string code, long length)
		{
			byte[] array = new byte[length];
			int num = int.Parse(code, NumberStyles.HexNumber);
			UIntPtr lpBaseAddress = (UIntPtr)((ulong)((long)num));
			bool flag = !Form1.ReadProcessMemory(this.pHandle, lpBaseAddress, array, (UIntPtr)((ulong)length), IntPtr.Zero);
			byte[] result;
			if (flag)
			{
				result = null;
			}
			else
			{
				result = array;
			}
			return result;
		}

		// Token: 0x06000041 RID: 65 RVA: 0x00002A14 File Offset: 0x00000C14
		public byte[] ReadByte(int code, string file = "")
		{
			byte[] array = new byte[1];
			UIntPtr lpBaseAddress = (UIntPtr)((ulong)((long)code));
			bool flag = Form1.ReadProcessMemory(this.pHandle, lpBaseAddress, array, (UIntPtr)1UL, IntPtr.Zero);
			byte[] result;
			if (flag)
			{
				result = array;
			}
			else
			{
				result = null;
			}
			return result;
		}

		// Token: 0x06000042 RID: 66 RVA: 0x00002A58 File Offset: 0x00000C58
		public float ReadFloat(string code, string file = "", bool round = true)
		{
			byte[] array = new byte[4];
			UIntPtr code2 = this.GetCode(code, file, 8);
			float result;
			try
			{
				bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)4UL, IntPtr.Zero);
				if (flag)
				{
					float num = BitConverter.ToSingle(array, 0);
					float num2 = num;
					if (round)
					{
						num2 = (float)Math.Round((double)num, 2);
					}
					result = num2;
				}
				else
				{
					result = 0f;
				}
			}
			catch
			{
				result = 0f;
			}
			return result;
		}

		// Token: 0x06000043 RID: 67 RVA: 0x00002AE4 File Offset: 0x00000CE4
		public string ReadString(string code, string file = "", int length = 32, bool zeroTerminated = true)
		{
			byte[] array = new byte[length];
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)((ulong)((long)length)), IntPtr.Zero);
			string result;
			if (flag)
			{
				result = (zeroTerminated ? Encoding.UTF8.GetString(array).Split(new char[1])[0] : Encoding.UTF8.GetString(array));
			}
			else
			{
				result = "";
			}
			return result;
		}

		// Token: 0x06000044 RID: 68 RVA: 0x00002B58 File Offset: 0x00000D58
		public double ReadDouble(string code, string file = "", bool round = true)
		{
			byte[] array = new byte[8];
			UIntPtr code2 = this.GetCode(code, file, 8);
			double result;
			try
			{
				bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)8UL, IntPtr.Zero);
				if (flag)
				{
					double num = BitConverter.ToDouble(array, 0);
					double num2 = num;
					if (round)
					{
						num2 = Math.Round(num, 2);
					}
					result = num2;
				}
				else
				{
					result = 0.0;
				}
			}
			catch
			{
				result = 0.0;
			}
			return result;
		}

		// Token: 0x06000045 RID: 69 RVA: 0x00002BE8 File Offset: 0x00000DE8
		public int ReadUIntPtr(UIntPtr code)
		{
			byte[] array = new byte[4];
			bool flag = Form1.ReadProcessMemory(this.pHandle, code, array, (UIntPtr)4UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x06000046 RID: 70 RVA: 0x00002C2C File Offset: 0x00000E2C
		public int ReadInt(string code, string file = "")
		{
			byte[] array = new byte[4];
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)4UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x06000047 RID: 71 RVA: 0x00002C78 File Offset: 0x00000E78
		public long ReadLong(string code, string file = "")
		{
			byte[] array = new byte[16];
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)16UL, IntPtr.Zero);
			long result;
			if (flag)
			{
				result = BitConverter.ToInt64(array, 0);
			}
			else
			{
				result = 0L;
			}
			return result;
		}

		// Token: 0x06000048 RID: 72 RVA: 0x00002CC8 File Offset: 0x00000EC8
		public ulong ReadUInt(string code, string file = "")
		{
			byte[] array = new byte[4];
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)4UL, IntPtr.Zero);
			ulong result;
			if (flag)
			{
				result = BitConverter.ToUInt64(array, 0);
			}
			else
			{
				result = 0UL;
			}
			return result;
		}

		// Token: 0x06000049 RID: 73 RVA: 0x00002D18 File Offset: 0x00000F18
		public int Read2ByteMove(string code, int moveQty, string file = "")
		{
			byte[] array = new byte[4];
			UIntPtr code2 = this.GetCode(code, file, 8);
			UIntPtr lpBaseAddress = UIntPtr.Add(code2, moveQty);
			bool flag = Form1.ReadProcessMemory(this.pHandle, lpBaseAddress, array, (UIntPtr)2UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x0600004A RID: 74 RVA: 0x00002D70 File Offset: 0x00000F70
		public int ReadIntMove(string code, int moveQty, string file = "")
		{
			byte[] array = new byte[4];
			UIntPtr code2 = this.GetCode(code, file, 8);
			UIntPtr lpBaseAddress = UIntPtr.Add(code2, moveQty);
			bool flag = Form1.ReadProcessMemory(this.pHandle, lpBaseAddress, array, (UIntPtr)4UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x0600004B RID: 75 RVA: 0x00002DC8 File Offset: 0x00000FC8
		public ulong ReadUIntMove(string code, int moveQty, string file = "")
		{
			byte[] array = new byte[8];
			UIntPtr code2 = this.GetCode(code, file, 8);
			UIntPtr lpBaseAddress = UIntPtr.Add(code2, moveQty);
			bool flag = Form1.ReadProcessMemory(this.pHandle, lpBaseAddress, array, (UIntPtr)8UL, IntPtr.Zero);
			ulong result;
			if (flag)
			{
				result = BitConverter.ToUInt64(array, 0);
			}
			else
			{
				result = 0UL;
			}
			return result;
		}

		// Token: 0x0600004C RID: 76 RVA: 0x00002E20 File Offset: 0x00001020
		public int Read2Byte(string code, string file = "")
		{
			byte[] array = new byte[4];
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)2UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x0600004D RID: 77 RVA: 0x00002E6C File Offset: 0x0000106C
		public bool[] ReadBits(string code, string file = "")
		{
			byte[] array = new byte[1];
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool[] array2 = new bool[8];
			bool flag = !Form1.ReadProcessMemory(this.pHandle, code2, array, (UIntPtr)1UL, IntPtr.Zero);
			bool[] result;
			if (flag)
			{
				result = array2;
			}
			else
			{
				bool flag2 = !BitConverter.IsLittleEndian;
				if (flag2)
				{
					throw new Exception("Should be little endian");
				}
				for (int i = 0; i < 8; i++)
				{
					array2[i] = Convert.ToBoolean((int)array[0] & 1 << i);
				}
				result = array2;
			}
			return result;
		}

		// Token: 0x0600004E RID: 78 RVA: 0x00002F08 File Offset: 0x00001108
		public int ReadPByte(UIntPtr address, string code, string file = "")
		{
			byte[] array = new byte[4];
			bool flag = Form1.ReadProcessMemory(this.pHandle, address + this.LoadIntCode(code, file), array, (UIntPtr)1UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x0600004F RID: 79 RVA: 0x00002F58 File Offset: 0x00001158
		public float ReadPFloat(UIntPtr address, string code, string file = "")
		{
			byte[] array = new byte[4];
			bool flag = Form1.ReadProcessMemory(this.pHandle, address + this.LoadIntCode(code, file), array, (UIntPtr)4UL, IntPtr.Zero);
			float result;
			if (flag)
			{
				float num = BitConverter.ToSingle(array, 0);
				result = (float)Math.Round((double)num, 2);
			}
			else
			{
				result = 0f;
			}
			return result;
		}

		// Token: 0x06000050 RID: 80 RVA: 0x00002FB8 File Offset: 0x000011B8
		public int ReadPInt(UIntPtr address, string code, string file = "")
		{
			byte[] array = new byte[4];
			bool flag = Form1.ReadProcessMemory(this.pHandle, address + this.LoadIntCode(code, file), array, (UIntPtr)4UL, IntPtr.Zero);
			int result;
			if (flag)
			{
				result = BitConverter.ToInt32(array, 0);
			}
			else
			{
				result = 0;
			}
			return result;
		}

		// Token: 0x06000051 RID: 81 RVA: 0x00003008 File Offset: 0x00001208
		public string ReadPString(UIntPtr address, string code, string file = "")
		{
			byte[] array = new byte[32];
			bool flag = Form1.ReadProcessMemory(this.pHandle, address + this.LoadIntCode(code, file), array, (UIntPtr)32UL, IntPtr.Zero);
			string result;
			if (flag)
			{
				result = this.CutString(Encoding.ASCII.GetString(array));
			}
			else
			{
				result = "";
			}
			return result;
		}

		// Token: 0x06000052 RID: 82 RVA: 0x00003068 File Offset: 0x00001268
		public bool WriteMemory(string code, string type, string write, string file = "", Encoding stringEncoding = null)
		{
			byte[] array = new byte[4];
			int num = 4;
			UIntPtr code2 = this.GetCode(code, file, 8);
			bool flag = type.ToLower() == "float";
			if (flag)
			{
				array = BitConverter.GetBytes(Convert.ToSingle(write));
				num = 4;
			}
			else
			{
				bool flag2 = type.ToLower() == "int";
				if (flag2)
				{
					array = BitConverter.GetBytes(Convert.ToInt32(write));
					num = 4;
				}
				else
				{
					bool flag3 = type.ToLower() == "byte";
					if (flag3)
					{
						array = new byte[]
						{
							Convert.ToByte(write, 16)
						};
						num = 1;
					}
					else
					{
						bool flag4 = type.ToLower() == "2bytes";
						if (flag4)
						{
							array = new byte[]
							{
								(byte)(Convert.ToInt32(write) % 256),
								(byte)(Convert.ToInt32(write) / 256)
							};
							num = 2;
						}
						else
						{
							bool flag5 = type.ToLower() == "bytes";
							if (flag5)
							{
								bool flag6 = write.Contains(",") || write.Contains(" ");
								if (flag6)
								{
									string[] array2 = (!write.Contains(",")) ? write.Split(new char[]
									{
										' '
									}) : write.Split(new char[]
									{
										','
									});
									int num2 = array2.Count<string>();
									array = new byte[num2];
									for (int i = 0; i < num2; i++)
									{
										array[i] = Convert.ToByte(array2[i], 16);
									}
									num = array2.Count<string>();
								}
								else
								{
									array = new byte[]
									{
										Convert.ToByte(write, 16)
									};
									num = 1;
								}
							}
							else
							{
								bool flag7 = type.ToLower() == "double";
								if (flag7)
								{
									array = BitConverter.GetBytes(Convert.ToDouble(write));
									num = 8;
								}
								else
								{
									bool flag8 = type.ToLower() == "long";
									if (flag8)
									{
										array = BitConverter.GetBytes(Convert.ToInt64(write));
										num = 8;
									}
									else
									{
										bool flag9 = type.ToLower() == "string";
										if (flag9)
										{
											array = ((stringEncoding != null) ? stringEncoding.GetBytes(write) : Encoding.UTF8.GetBytes(write));
											num = array.Length;
										}
									}
								}
							}
						}
					}
				}
			}
			return Form1.WriteProcessMemory(this.pHandle, code2, array, (UIntPtr)((ulong)((long)num)), IntPtr.Zero);
		}

		// Token: 0x06000053 RID: 83 RVA: 0x000032CC File Offset: 0x000014CC
		public bool WriteMove(string code, string type, string write, int moveQty, string file = "")
		{
			byte[] array = new byte[4];
			int num = 4;
			UIntPtr code2 = this.GetCode(code, file, 8);
			if (!(type == "float"))
			{
				if (!(type == "int"))
				{
					if (!(type == "double"))
					{
						if (!(type == "long"))
						{
							if (!(type == "byte"))
							{
								if (type == "string")
								{
									array = new byte[write.Length];
									array = Encoding.UTF8.GetBytes(write);
									num = write.Length;
								}
							}
							else
							{
								array = new byte[]
								{
									Convert.ToByte(write, 16)
								};
								num = 1;
							}
						}
						else
						{
							array = BitConverter.GetBytes(Convert.ToInt64(write));
							num = 8;
						}
					}
					else
					{
						array = BitConverter.GetBytes(Convert.ToDouble(write));
						num = 8;
					}
				}
				else
				{
					array = BitConverter.GetBytes(Convert.ToInt32(write));
					num = 4;
				}
			}
			else
			{
				array = new byte[write.Length];
				array = BitConverter.GetBytes(Convert.ToSingle(write));
				num = write.Length;
			}
			UIntPtr lpBaseAddress = UIntPtr.Add(code2, moveQty);
			Debug.Write(string.Concat(new string[]
			{
				"DEBUG: Writing bytes [TYPE:",
				type,
				" ADDR:[O]",
				code2.ToString(),
				" [N]",
				lpBaseAddress.ToString(),
				" MQTY:",
				moveQty.ToString(),
				"] ",
				string.Join<byte>(",", array),
				Environment.NewLine
			}));
			Thread.Sleep(1000);
			return Form1.WriteProcessMemory(this.pHandle, lpBaseAddress, array, (UIntPtr)((ulong)((long)num)), IntPtr.Zero);
		}

		// Token: 0x06000054 RID: 84 RVA: 0x00003480 File Offset: 0x00001680
		public void WriteBytes(string code, byte[] write, string file = "")
		{
			UIntPtr code2 = this.GetCode(code, file, 8);
			Form1.WriteProcessMemory(this.pHandle, code2, write, (UIntPtr)((ulong)((long)write.Length)), IntPtr.Zero);
		}

		// Token: 0x06000055 RID: 85 RVA: 0x000034B4 File Offset: 0x000016B4
		public void WriteBits(string code, bool[] bits, string file = "")
		{
			bool flag = bits.Length != 8;
			if (flag)
			{
				throw new ArgumentException("Not enough bits for a whole byte", "bits");
			}
			byte[] array = new byte[1];
			UIntPtr code2 = this.GetCode(code, file, 8);
			for (int i = 0; i < 8; i++)
			{
				bool flag2 = bits[i];
				if (flag2)
				{
					byte[] array2 = array;
					int num = 0;
					array2[num] |= (byte)(1 << i);
				}
			}
			Form1.WriteProcessMemory(this.pHandle, code2, array, (UIntPtr)1UL, IntPtr.Zero);
		}

		// Token: 0x06000056 RID: 86 RVA: 0x00003540 File Offset: 0x00001740
		public void WriteBytes(UIntPtr address, byte[] write)
		{
			IntPtr intPtr;
			Form1.WriteProcessMemory(this.pHandle, address, write, (UIntPtr)((ulong)((long)write.Length)), out intPtr);
		}

		// Token: 0x06000057 RID: 87 RVA: 0x00003568 File Offset: 0x00001768
		public UIntPtr GetCode(string name, string path = "", int size = 8)
		{
			bool is64Bit = this.Is64Bit;
			UIntPtr result;
			if (is64Bit)
			{
				bool flag = size == 8;
				if (flag)
				{
					size = 16;
				}
				result = this.Get64BitCode(name, path, size);
			}
			else
			{
				string text = (!(path != "")) ? name : this.LoadCode(name, path);
				bool flag2 = text == "";
				if (flag2)
				{
					result = UIntPtr.Zero;
				}
				else
				{
					bool flag3 = text.Contains(" ");
					if (flag3)
					{
						text.Replace(" ", string.Empty);
					}
					bool flag4 = !text.Contains("+") && !text.Contains(",");
					if (flag4)
					{
						result = new UIntPtr(Convert.ToUInt32(text, 16));
					}
					else
					{
						string text2 = text;
						bool flag5 = text.Contains("+");
						if (flag5)
						{
							text2 = text.Substring(text.IndexOf('+') + 1);
						}
						byte[] array = new byte[size];
						bool flag6 = text2.Contains(',');
						if (flag6)
						{
							List<int> list = new List<int>();
							string[] array2 = text2.Split(new char[]
							{
								','
							});
							string[] array3 = array2;
							foreach (string text3 in array3)
							{
								string text4 = text3;
								bool flag7 = text3.Contains("0x");
								if (flag7)
								{
									text4 = text3.Replace("0x", "");
								}
								bool flag8 = !text3.Contains("-");
								int num;
								if (flag8)
								{
									num = int.Parse(text4, NumberStyles.AllowHexSpecifier);
								}
								else
								{
									text4 = text4.Replace("-", "");
									num = int.Parse(text4, NumberStyles.AllowHexSpecifier);
									num *= -1;
								}
								list.Add(num);
							}
							int[] array5 = list.ToArray();
							bool flag9 = text.Contains("base") || text.Contains("main");
							if (flag9)
							{
								Form1.ReadProcessMemory(this.pHandle, (UIntPtr)((ulong)((long)((int)this.mainModule.BaseAddress + array5[0]))), array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
							}
							else
							{
								bool flag10 = !text.Contains("base") && !text.Contains("main") && text.Contains("+");
								if (flag10)
								{
									string[] array6 = text.Split(new char[]
									{
										'+'
									});
									IntPtr value = IntPtr.Zero;
									bool flag11 = !array6[0].ToLower().Contains(".dll") && !array6[0].ToLower().Contains(".exe") && !array6[0].ToLower().Contains(".bin");
									if (flag11)
									{
										string text5 = array6[0];
										bool flag12 = text5.Contains("0x");
										if (flag12)
										{
											text5 = text5.Replace("0x", "");
										}
										value = (IntPtr)int.Parse(text5, NumberStyles.HexNumber);
									}
									else
									{
										try
										{
											value = this.modules[array6[0]];
										}
										catch
										{
											Debug.WriteLine("Module " + array6[0] + " was not found in module list!");
											Debug.WriteLine("Modules: " + string.Join<KeyValuePair<string, IntPtr>>(",", this.modules));
										}
									}
									Form1.ReadProcessMemory(this.pHandle, (UIntPtr)((ulong)((long)((int)value + array5[0]))), array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
								}
								else
								{
									Form1.ReadProcessMemory(this.pHandle, (UIntPtr)((ulong)((long)array5[0])), array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
								}
							}
							uint num2 = BitConverter.ToUInt32(array, 0);
							UIntPtr uintPtr = (UIntPtr)0UL;
							for (int j = 1; j < array5.Length; j++)
							{
								uintPtr = new UIntPtr(Convert.ToUInt32((long)((ulong)num2 + (ulong)((long)array5[j]))));
								Form1.ReadProcessMemory(this.pHandle, uintPtr, array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
								num2 = BitConverter.ToUInt32(array, 0);
							}
							result = uintPtr;
						}
						else
						{
							int num3 = Convert.ToInt32(text2, 16);
							IntPtr value2 = IntPtr.Zero;
							bool flag13 = text.ToLower().Contains("base") || text.ToLower().Contains("main");
							if (flag13)
							{
								value2 = this.mainModule.BaseAddress;
							}
							else
							{
								bool flag14 = !text.ToLower().Contains("base") && !text.ToLower().Contains("main") && text.Contains("+");
								if (flag14)
								{
									string[] array7 = text.Split(new char[]
									{
										'+'
									});
									bool flag15 = !array7[0].ToLower().Contains(".dll") && !array7[0].ToLower().Contains(".exe") && !array7[0].ToLower().Contains(".bin");
									if (flag15)
									{
										string text6 = array7[0];
										bool flag16 = text6.Contains("0x");
										if (flag16)
										{
											text6 = text6.Replace("0x", "");
										}
										value2 = (IntPtr)int.Parse(text6, NumberStyles.HexNumber);
									}
									else
									{
										try
										{
											value2 = this.modules[array7[0]];
										}
										catch
										{
											Debug.WriteLine("Module " + array7[0] + " was not found in module list!");
											Debug.WriteLine("Modules: " + string.Join<KeyValuePair<string, IntPtr>>(",", this.modules));
										}
									}
								}
								else
								{
									value2 = this.modules[text.Split(new char[]
									{
										'+'
									})[0]];
								}
							}
							result = (UIntPtr)((ulong)((long)((int)value2 + num3)));
						}
					}
				}
			}
			return result;
		}

		// Token: 0x06000058 RID: 88 RVA: 0x00003B78 File Offset: 0x00001D78
		public UIntPtr Get64BitCode(string name, string path = "", int size = 16)
		{
			string text = (!(path != "")) ? name : this.LoadCode(name, path);
			bool flag = text == "";
			UIntPtr result;
			if (flag)
			{
				result = UIntPtr.Zero;
			}
			else
			{
				bool flag2 = text.Contains(" ");
				if (flag2)
				{
					text.Replace(" ", string.Empty);
				}
				string text2 = text;
				bool flag3 = text.Contains("+");
				if (flag3)
				{
					text2 = text.Substring(text.IndexOf('+') + 1);
				}
				byte[] array = new byte[size];
				bool flag4 = !text.Contains("+") && !text.Contains(",");
				if (flag4)
				{
					result = new UIntPtr(Convert.ToUInt64(text, 16));
				}
				else
				{
					bool flag5 = text2.Contains(',');
					if (flag5)
					{
						List<long> list = new List<long>();
						string[] array2 = text2.Split(new char[]
						{
							','
						});
						string[] array3 = array2;
						foreach (string text3 in array3)
						{
							string text4 = text3;
							bool flag6 = text3.Contains("0x");
							if (flag6)
							{
								text4 = text3.Replace("0x", "");
							}
							bool flag7 = !text3.Contains("-");
							long num;
							if (flag7)
							{
								num = long.Parse(text4, NumberStyles.AllowHexSpecifier);
							}
							else
							{
								text4 = text4.Replace("-", "");
								num = long.Parse(text4, NumberStyles.AllowHexSpecifier);
								num *= -1L;
							}
							list.Add(num);
						}
						long[] array5 = list.ToArray();
						bool flag8 = text.Contains("base") || text.Contains("main");
						if (flag8)
						{
							Form1.ReadProcessMemory(this.pHandle, (UIntPtr)((ulong)((long)this.mainModule.BaseAddress + array5[0])), array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
						}
						else
						{
							bool flag9 = !text.Contains("base") && !text.Contains("main") && text.Contains("+");
							if (flag9)
							{
								string[] array6 = text.Split(new char[]
								{
									'+'
								});
								IntPtr value = IntPtr.Zero;
								bool flag10 = !array6[0].ToLower().Contains(".dll") && !array6[0].ToLower().Contains(".exe") && !array6[0].ToLower().Contains(".bin");
								if (flag10)
								{
									value = (IntPtr)long.Parse(array6[0], NumberStyles.HexNumber);
								}
								else
								{
									try
									{
										value = this.modules[array6[0]];
									}
									catch
									{
										Debug.WriteLine("Module " + array6[0] + " was not found in module list!");
										Debug.WriteLine("Modules: " + string.Join<KeyValuePair<string, IntPtr>>(",", this.modules));
									}
								}
								Form1.ReadProcessMemory(this.pHandle, (UIntPtr)((ulong)((long)value + array5[0])), array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
							}
							else
							{
								Form1.ReadProcessMemory(this.pHandle, (UIntPtr)((ulong)array5[0]), array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
							}
						}
						long num2 = BitConverter.ToInt64(array, 0);
						UIntPtr uintPtr = (UIntPtr)0UL;
						for (int j = 1; j < array5.Length; j++)
						{
							uintPtr = new UIntPtr(Convert.ToUInt64(num2 + array5[j]));
							Form1.ReadProcessMemory(this.pHandle, uintPtr, array, (UIntPtr)((ulong)((long)size)), IntPtr.Zero);
							num2 = BitConverter.ToInt64(array, 0);
						}
						result = uintPtr;
					}
					else
					{
						long num3 = Convert.ToInt64(text2, 16);
						IntPtr value2 = IntPtr.Zero;
						bool flag11 = text.Contains("base") || text.Contains("main");
						if (flag11)
						{
							value2 = this.mainModule.BaseAddress;
						}
						else
						{
							bool flag12 = !text.Contains("base") && !text.Contains("main") && text.Contains("+");
							if (flag12)
							{
								string[] array7 = text.Split(new char[]
								{
									'+'
								});
								bool flag13 = !array7[0].ToLower().Contains(".dll") && !array7[0].ToLower().Contains(".exe") && !array7[0].ToLower().Contains(".bin");
								if (flag13)
								{
									string text5 = array7[0];
									bool flag14 = text5.Contains("0x");
									if (flag14)
									{
										text5 = text5.Replace("0x", "");
									}
									value2 = (IntPtr)long.Parse(text5, NumberStyles.HexNumber);
								}
								else
								{
									try
									{
										value2 = this.modules[array7[0]];
									}
									catch
									{
										Debug.WriteLine("Module " + array7[0] + " was not found in module list!");
										Debug.WriteLine("Modules: " + string.Join<KeyValuePair<string, IntPtr>>(",", this.modules));
									}
								}
							}
							else
							{
								value2 = this.modules[text.Split(new char[]
								{
									'+'
								})[0]];
							}
						}
						result = (UIntPtr)((ulong)((long)value2 + num3));
					}
				}
			}
			return result;
		}

		// Token: 0x06000059 RID: 89 RVA: 0x00004118 File Offset: 0x00002318
		public void CloseProcess()
		{
			IntPtr intPtr = this.pHandle;
			Form1.CloseHandle(this.pHandle);
			this.theProc = null;
		}

		// Token: 0x0600005A RID: 90 RVA: 0x00004144 File Offset: 0x00002344
		public void InjectDll(string strDllName)
		{
			foreach (object obj in this.theProc.Modules)
			{
				ProcessModule processModule = (ProcessModule)obj;
				bool flag = processModule.ModuleName.StartsWith("inject", StringComparison.InvariantCultureIgnoreCase);
				if (flag)
				{
					return;
				}
			}
			bool responding = this.theProc.Responding;
			if (responding)
			{
				int num = strDllName.Length + 1;
				UIntPtr uintPtr = Form1.VirtualAllocEx(this.pHandle, (UIntPtr)null, (uint)num, 12288U, 4U);
				IntPtr intPtr;
				Form1.WriteProcessMemory(this.pHandle, uintPtr, strDllName, (UIntPtr)((ulong)((long)num)), out intPtr);
				UIntPtr procAddress = Form1.GetProcAddress(Form1.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
				IntPtr intPtr2 = Form1.CreateRemoteThread(this.pHandle, (IntPtr)null, 0U, procAddress, uintPtr, 0U, out intPtr);
				int num2 = Form1.WaitForSingleObject(intPtr2, 10000);
				bool flag2 = (long)num2 == 128L || (long)num2 == 258L;
				if (flag2)
				{
					Form1.CloseHandle(intPtr2);
				}
				else
				{
					Form1.VirtualFreeEx(this.pHandle, uintPtr, (UIntPtr)0UL, 32768U);
					Form1.CloseHandle(intPtr2);
				}
			}
		}

		// Token: 0x0600005B RID: 91 RVA: 0x000042AC File Offset: 0x000024AC
		public UIntPtr CreateCodeCave(string code, byte[] newBytes, int replaceCount, int size = 4096, string file = "")
		{
			bool flag = replaceCount < 5;
			UIntPtr result;
			if (flag)
			{
				result = UIntPtr.Zero;
			}
			else
			{
				UIntPtr code2 = this.GetCode(code, file, 8);
				UIntPtr uintPtr = code2;
				UIntPtr uintPtr2 = UIntPtr.Zero;
				UIntPtr uintPtr3 = uintPtr;
				for (int i = 0; i < 10; i++)
				{
					bool flag2 = !(uintPtr2 == UIntPtr.Zero);
					if (flag2)
					{
						break;
					}
					uintPtr2 = Form1.VirtualAllocEx(this.pHandle, this.FindFreeBlockForRegion(uintPtr3, (uint)size), (uint)size, 12288U, 64U);
					bool flag3 = uintPtr2 == UIntPtr.Zero;
					if (flag3)
					{
						uintPtr3 = UIntPtr.Add(uintPtr3, 65536);
					}
				}
				bool flag4 = uintPtr2 == UIntPtr.Zero;
				if (flag4)
				{
					uintPtr2 = Form1.VirtualAllocEx(this.pHandle, UIntPtr.Zero, (uint)size, 12288U, 64U);
				}
				int num = (replaceCount > 5) ? (replaceCount - 5) : 0;
				int value = (int)((ulong)uintPtr2 - (ulong)uintPtr - 5UL);
				byte[] array = new byte[5 + num];
				array[0] = 233;
				BitConverter.GetBytes(value).CopyTo(array, 1);
				for (int j = 5; j < array.Length; j++)
				{
					array[j] = 144;
				}
				this.WriteBytes(uintPtr, array);
				byte[] array2 = new byte[5 + newBytes.Length];
				value = (int)((ulong)uintPtr + (ulong)((long)array.Length) - ((ulong)uintPtr2 + (ulong)((long)newBytes.Length)) - 5UL);
				newBytes.CopyTo(array2, 0);
				array2[newBytes.Length] = 233;
				BitConverter.GetBytes(value).CopyTo(array2, newBytes.Length + 1);
				this.WriteBytes(uintPtr2, array2);
				result = uintPtr2;
			}
			return result;
		}

		// Token: 0x0600005C RID: 92 RVA: 0x00004458 File Offset: 0x00002658
		private UIntPtr FindFreeBlockForRegion(UIntPtr baseAddress, uint size)
		{
			UIntPtr uintPtr = UIntPtr.Subtract(baseAddress, 1879048192);
			UIntPtr value = UIntPtr.Add(baseAddress, 1879048192);
			UIntPtr uintPtr2 = UIntPtr.Zero;
			UIntPtr uintPtr3 = UIntPtr.Zero;
			Form1.SYSTEM_INFO system_INFO;
			Form1.GetSystemInfo(out system_INFO);
			bool is64Bit = this.Is64Bit;
			if (is64Bit)
			{
				bool flag = (ulong)uintPtr > (ulong)system_INFO.maximumApplicationAddress || (ulong)uintPtr < (ulong)system_INFO.minimumApplicationAddress;
				if (flag)
				{
					uintPtr = system_INFO.minimumApplicationAddress;
				}
				bool flag2 = (ulong)value < (ulong)system_INFO.minimumApplicationAddress || (ulong)value > (ulong)system_INFO.maximumApplicationAddress;
				if (flag2)
				{
					value = system_INFO.maximumApplicationAddress;
				}
			}
			else
			{
				uintPtr = system_INFO.minimumApplicationAddress;
				value = system_INFO.maximumApplicationAddress;
			}
			UIntPtr uintPtr4 = uintPtr;
			Form1.MEMORY_BASIC_INFORMATION memory_BASIC_INFORMATION;
			while (this.VirtualQueryEx(this.pHandle, uintPtr4, out memory_BASIC_INFORMATION).ToUInt64() > 0UL)
			{
				bool flag3 = (ulong)memory_BASIC_INFORMATION.BaseAddress > (ulong)value;
				UIntPtr result;
				if (flag3)
				{
					result = UIntPtr.Zero;
				}
				else
				{
					bool flag4 = memory_BASIC_INFORMATION.State == 65536U && memory_BASIC_INFORMATION.RegionSize > (long)((ulong)size);
					if (flag4)
					{
						bool flag5 = (ulong)memory_BASIC_INFORMATION.BaseAddress % (ulong)system_INFO.allocationGranularity > 0UL;
						if (flag5)
						{
							uintPtr3 = memory_BASIC_INFORMATION.BaseAddress;
							int num = (int)((ulong)system_INFO.allocationGranularity - (ulong)uintPtr3 % (ulong)system_INFO.allocationGranularity);
							bool flag6 = memory_BASIC_INFORMATION.RegionSize - (long)num >= (long)((ulong)size);
							if (flag6)
							{
								uintPtr3 = UIntPtr.Add(uintPtr3, num);
								bool flag7 = (ulong)uintPtr3 < (ulong)baseAddress;
								if (flag7)
								{
									uintPtr3 = UIntPtr.Add(uintPtr3, (int)(memory_BASIC_INFORMATION.RegionSize - (long)num - (long)((ulong)size)));
									bool flag8 = (ulong)uintPtr3 > (ulong)baseAddress;
									if (flag8)
									{
										uintPtr3 = baseAddress;
									}
									uintPtr3 = UIntPtr.Subtract(uintPtr3, (int)((ulong)uintPtr3 % (ulong)system_INFO.allocationGranularity));
								}
								bool flag9 = Math.Abs((long)((ulong)uintPtr3 - (ulong)baseAddress)) < Math.Abs((long)((ulong)uintPtr2 - (ulong)baseAddress));
								if (flag9)
								{
									uintPtr2 = uintPtr3;
								}
							}
						}
						else
						{
							uintPtr3 = memory_BASIC_INFORMATION.BaseAddress;
							bool flag10 = (ulong)uintPtr3 < (ulong)baseAddress;
							if (flag10)
							{
								uintPtr3 = UIntPtr.Add(uintPtr3, (int)(memory_BASIC_INFORMATION.RegionSize - (long)((ulong)size)));
								bool flag11 = (ulong)uintPtr3 > (ulong)baseAddress;
								if (flag11)
								{
									uintPtr3 = baseAddress;
								}
								uintPtr3 = UIntPtr.Subtract(uintPtr3, (int)((ulong)uintPtr3 % (ulong)system_INFO.allocationGranularity));
							}
							bool flag12 = Math.Abs((long)((ulong)uintPtr3 - (ulong)baseAddress)) < Math.Abs((long)((ulong)uintPtr2 - (ulong)baseAddress));
							if (flag12)
							{
								uintPtr2 = uintPtr3;
							}
						}
					}
					bool flag13 = memory_BASIC_INFORMATION.RegionSize % (long)((ulong)system_INFO.allocationGranularity) > 0L;
					if (flag13)
					{
						memory_BASIC_INFORMATION.RegionSize += (long)((ulong)system_INFO.allocationGranularity - (ulong)(memory_BASIC_INFORMATION.RegionSize % (long)((ulong)system_INFO.allocationGranularity)));
					}
					UIntPtr value2 = uintPtr4;
					uintPtr4 = UIntPtr.Add(memory_BASIC_INFORMATION.BaseAddress, (int)memory_BASIC_INFORMATION.RegionSize);
					bool flag14 = (ulong)uintPtr4 > (ulong)value;
					if (flag14)
					{
						result = uintPtr2;
					}
					else
					{
						bool flag15 = (ulong)value2 > (ulong)uintPtr4;
						if (!flag15)
						{
							continue;
						}
						result = uintPtr2;
					}
				}
				return result;
			}
			return uintPtr2;
		}

		// Token: 0x0600005D RID: 93 RVA: 0x000047D4 File Offset: 0x000029D4
		public static void SuspendProcess(int pid)
		{
			Process processById = Process.GetProcessById(pid);
			bool flag = processById.ProcessName == string.Empty;
			if (!flag)
			{
				foreach (object obj in processById.Threads)
				{
					ProcessThread processThread = (ProcessThread)obj;
					IntPtr intPtr = Form1.OpenThread(Form1.ThreadAccess.SUSPEND_RESUME, false, (uint)processThread.Id);
					bool flag2 = !(intPtr == IntPtr.Zero);
					if (flag2)
					{
						Form1.SuspendThread(intPtr);
						Form1.CloseHandle(intPtr);
					}
				}
			}
		}

		// Token: 0x0600005E RID: 94 RVA: 0x00004884 File Offset: 0x00002A84
		public static void ResumeProcess(int pid)
		{
			Process processById = Process.GetProcessById(pid);
			bool flag = processById.ProcessName == string.Empty;
			if (!flag)
			{
				foreach (object obj in processById.Threads)
				{
					ProcessThread processThread = (ProcessThread)obj;
					IntPtr intPtr = Form1.OpenThread(Form1.ThreadAccess.SUSPEND_RESUME, false, (uint)processThread.Id);
					bool flag2 = !(intPtr == IntPtr.Zero);
					if (flag2)
					{
						int num;
						do
						{
							num = Form1.ResumeThread(intPtr);
						}
						while (num > 0);
						Form1.CloseHandle(intPtr);
					}
				}
			}
		}

		// Token: 0x0600005F RID: 95 RVA: 0x00004948 File Offset: 0x00002B48
		[DebuggerStepThrough]
		private Task PutTaskDelay(int delay)
		{
			Form1.<PutTaskDelay>d__159 <PutTaskDelay>d__ = new Form1.<PutTaskDelay>d__159();
			<PutTaskDelay>d__.<>t__builder = AsyncTaskMethodBuilder.Create();
			<PutTaskDelay>d__.<>4__this = this;
			<PutTaskDelay>d__.delay = delay;
			<PutTaskDelay>d__.<>1__state = -1;
			<PutTaskDelay>d__.<>t__builder.Start<Form1.<PutTaskDelay>d__159>(ref <PutTaskDelay>d__);
			return <PutTaskDelay>d__.<>t__builder.Task;
		}

		// Token: 0x06000060 RID: 96 RVA: 0x00004994 File Offset: 0x00002B94
		public byte[] FileToBytes(string path, bool dontDelete = false)
		{
			byte[] result = File.ReadAllBytes(path);
			bool flag = !dontDelete;
			if (flag)
			{
				File.Delete(path);
			}
			return result;
		}

		// Token: 0x06000061 RID: 97 RVA: 0x000049C0 File Offset: 0x00002BC0
		public string MSize()
		{
			bool is64Bit = this.Is64Bit;
			string result;
			if (is64Bit)
			{
				result = "x16";
			}
			else
			{
				result = "x8";
			}
			return result;
		}

		// Token: 0x06000062 RID: 98 RVA: 0x000049EC File Offset: 0x00002BEC
		public static string ByteArrayToHexString(byte[] ba)
		{
			StringBuilder stringBuilder = new StringBuilder(ba.Length * 2);
			int num = 1;
			foreach (byte b in ba)
			{
				bool flag = num == 16;
				if (flag)
				{
					stringBuilder.AppendFormat("{0:x2}{1}", b, Environment.NewLine);
					num = 0;
				}
				else
				{
					stringBuilder.AppendFormat("{0:x2} ", b);
				}
				num++;
			}
			return stringBuilder.ToString().ToUpper();
		}

		// Token: 0x06000063 RID: 99 RVA: 0x00004A74 File Offset: 0x00002C74
		public static string ByteArrayToString(byte[] ba)
		{
			StringBuilder stringBuilder = new StringBuilder(ba.Length * 2);
			foreach (byte b in ba)
			{
				stringBuilder.AppendFormat("{0:x2} ", b);
			}
			return stringBuilder.ToString();
		}

		// Token: 0x06000064 RID: 100 RVA: 0x00004AC4 File Offset: 0x00002CC4
		public ulong GetMinAddress()
		{
			Form1.SYSTEM_INFO system_INFO;
			Form1.GetSystemInfo(out system_INFO);
			return (ulong)system_INFO.minimumApplicationAddress;
		}

		// Token: 0x06000065 RID: 101 RVA: 0x00004AEC File Offset: 0x00002CEC
		public bool DumpMemory(string file = "dump.dmp")
		{
			Debug.Write("[DEBUG] memory dump starting... (" + DateTime.Now.ToString("h:mm:ss tt") + ")" + Environment.NewLine);
			Form1.SYSTEM_INFO system_INFO = default(Form1.SYSTEM_INFO);
			Form1.GetSystemInfo(out system_INFO);
			UIntPtr minimumApplicationAddress = system_INFO.minimumApplicationAddress;
			UIntPtr maximumApplicationAddress = system_INFO.maximumApplicationAddress;
			long num = (long)((ulong)minimumApplicationAddress);
			long num2 = this.theProc.VirtualMemorySize64 + num;
			bool flag = File.Exists(file);
			if (flag)
			{
				File.Delete(file);
			}
			Form1.MEMORY_BASIC_INFORMATION memory_BASIC_INFORMATION = default(Form1.MEMORY_BASIC_INFORMATION);
			while (num < num2)
			{
				this.VirtualQueryEx(this.pHandle, minimumApplicationAddress, out memory_BASIC_INFORMATION);
				byte[] lpBuffer = new byte[memory_BASIC_INFORMATION.RegionSize];
				UIntPtr nSize = (UIntPtr)((ulong)memory_BASIC_INFORMATION.RegionSize);
				UIntPtr lpBaseAddress = (UIntPtr)((ulong)memory_BASIC_INFORMATION.BaseAddress);
				Form1.ReadProcessMemory(this.pHandle, lpBaseAddress, lpBuffer, nSize, IntPtr.Zero);
				num += memory_BASIC_INFORMATION.RegionSize;
				minimumApplicationAddress = new UIntPtr((ulong)num);
			}
			Debug.Write(string.Concat(new string[]
			{
				"[DEBUG] memory dump completed. Saving dump file to ",
				file,
				". (",
				DateTime.Now.ToString("h:mm:ss tt"),
				")",
				Environment.NewLine
			}));
			return true;
		}

		// Token: 0x06000066 RID: 102 RVA: 0x00004C44 File Offset: 0x00002E44
		public Task<IEnumerable<long>> AoBScan(string search, bool writable = false, bool executable = false, string file = "")
		{
			return this.AoBScan(0L, long.MaxValue, search, writable, executable, file);
		}

		// Token: 0x06000067 RID: 103 RVA: 0x00004C6C File Offset: 0x00002E6C
		public Task<IEnumerable<long>> AoBScan(string search, bool readable, bool writable, bool executable, string file = "")
		{
			return this.AoBScan(0L, long.MaxValue, search, readable, writable, executable, file);
		}

		// Token: 0x06000068 RID: 104 RVA: 0x00004C98 File Offset: 0x00002E98
		public Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool writable, bool executable, string file = "")
		{
			return this.AoBScan(start, end, search, true, writable, executable, file);
		}

		// Token: 0x06000069 RID: 105 RVA: 0x00004CBC File Offset: 0x00002EBC
		public Task<IEnumerable<long>> AoBScan(long start, long end, string search, bool readable, bool writable, bool executable, string file = "")
		{
			return Task.Run<IEnumerable<long>>(delegate()
			{
				List<Form1.MemoryRegionResult> list = new List<Form1.MemoryRegionResult>();
				string text = this.LoadCode(search, file);
				string[] array = text.Split(new char[]
				{
					' '
				});
				byte[] aobPattern = new byte[array.Length];
				byte[] mask = new byte[array.Length];
				for (int i = 0; i < array.Length; i++)
				{
					string text2 = array[i];
					bool flag = text2 == "??" || (text2.Length == 1 && text2 == "?");
					if (flag)
					{
						mask[i] = 0;
						array[i] = "0x00";
					}
					else
					{
						bool flag2 = char.IsLetterOrDigit(text2[0]) && text2[1] == '?';
						if (flag2)
						{
							mask[i] = 240;
							array[i] = text2[0].ToString() + "0";
						}
						else
						{
							bool flag3 = char.IsLetterOrDigit(text2[1]) && text2[0] == '?';
							if (flag3)
							{
								mask[i] = 15;
								array[i] = "0" + text2[1].ToString();
							}
							else
							{
								mask[i] = byte.MaxValue;
							}
						}
					}
				}
				for (int j = 0; j < array.Length; j++)
				{
					aobPattern[j] = (Convert.ToByte(array[j], 16) & mask[j]);
				}
				Form1.SYSTEM_INFO system_INFO = default(Form1.SYSTEM_INFO);
				Form1.GetSystemInfo(out system_INFO);
				UIntPtr minimumApplicationAddress = system_INFO.minimumApplicationAddress;
				UIntPtr maximumApplicationAddress = system_INFO.maximumApplicationAddress;
				bool flag4 = start < (long)minimumApplicationAddress.ToUInt64();
				if (flag4)
				{
					start = (long)minimumApplicationAddress.ToUInt64();
				}
				bool flag5 = end > (long)maximumApplicationAddress.ToUInt64();
				if (flag5)
				{
					end = (long)maximumApplicationAddress.ToUInt64();
				}
				Debug.WriteLine(string.Concat(new string[]
				{
					"[DEBUG] memory scan starting... (start:0x",
					start.ToString(this.MSize()),
					" end:0x",
					end.ToString(this.MSize()),
					" time:",
					DateTime.Now.ToString("h:mm:ss tt"),
					")"
				}));
				UIntPtr uintPtr = new UIntPtr((ulong)start);
				Form1.MEMORY_BASIC_INFORMATION memory_BASIC_INFORMATION = default(Form1.MEMORY_BASIC_INFORMATION);
				while (this.VirtualQueryEx(this.pHandle, uintPtr, out memory_BASIC_INFORMATION).ToUInt64() != 0UL && uintPtr.ToUInt64() < (ulong)end && uintPtr.ToUInt64() + (ulong)memory_BASIC_INFORMATION.RegionSize > uintPtr.ToUInt64())
				{
					bool flag6 = memory_BASIC_INFORMATION.State == 4096U;
					flag6 &= (memory_BASIC_INFORMATION.BaseAddress.ToUInt64() < maximumApplicationAddress.ToUInt64());
					flag6 &= ((memory_BASIC_INFORMATION.Protect & 256U) == 0U);
					flag6 &= ((memory_BASIC_INFORMATION.Protect & 1U) == 0U);
					flag6 &= (memory_BASIC_INFORMATION.Type == this.MEM_PRIVATE || memory_BASIC_INFORMATION.Type == this.MEM_IMAGE);
					bool flag7 = flag6;
					if (flag7)
					{
						bool flag8 = (memory_BASIC_INFORMATION.Protect & 2U) > 0U;
						bool flag9 = (memory_BASIC_INFORMATION.Protect & 4U) != 0U || (memory_BASIC_INFORMATION.Protect & 8U) != 0U || (memory_BASIC_INFORMATION.Protect & 64U) != 0U || (memory_BASIC_INFORMATION.Protect & 128U) > 0U;
						bool flag10 = (memory_BASIC_INFORMATION.Protect & 16U) != 0U || (memory_BASIC_INFORMATION.Protect & 32U) != 0U || (memory_BASIC_INFORMATION.Protect & 64U) != 0U || (memory_BASIC_INFORMATION.Protect & 128U) > 0U;
						flag8 &= readable;
						flag9 &= writable;
						flag10 &= executable;
						flag6 = (flag6 && (flag8 || flag9 || flag10));
					}
					bool flag11 = !flag6;
					if (flag11)
					{
						uintPtr = new UIntPtr(memory_BASIC_INFORMATION.BaseAddress.ToUInt64() + (ulong)memory_BASIC_INFORMATION.RegionSize);
					}
					else
					{
						Form1.MemoryRegionResult item2 = new Form1.MemoryRegionResult
						{
							CurrentBaseAddress = uintPtr,
							RegionSize = memory_BASIC_INFORMATION.RegionSize,
							RegionBase = memory_BASIC_INFORMATION.BaseAddress
						};
						uintPtr = new UIntPtr(memory_BASIC_INFORMATION.BaseAddress.ToUInt64() + (ulong)memory_BASIC_INFORMATION.RegionSize);
						bool flag12 = list.Count > 0;
						if (flag12)
						{
							Form1.MemoryRegionResult memoryRegionResult = list[list.Count - 1];
							bool flag13 = (ulong)memoryRegionResult.RegionBase + (ulong)memoryRegionResult.RegionSize == (ulong)memory_BASIC_INFORMATION.BaseAddress;
							if (flag13)
							{
								list[list.Count - 1] = new Form1.MemoryRegionResult
								{
									CurrentBaseAddress = memoryRegionResult.CurrentBaseAddress,
									RegionBase = memoryRegionResult.RegionBase,
									RegionSize = memoryRegionResult.RegionSize + memory_BASIC_INFORMATION.RegionSize
								};
								continue;
							}
						}
						list.Add(item2);
					}
				}
				ConcurrentBag<long> bagResult = new ConcurrentBag<long>();
				Parallel.ForEach<Form1.MemoryRegionResult>(list, delegate(Form1.MemoryRegionResult item, ParallelLoopState parallelLoopState, long index)
				{
					long[] array2 = this.CompareScan(item, aobPattern, mask);
					long[] array3 = array2;
					foreach (long item3 in array3)
					{
						bagResult.Add(item3);
					}
				});
				Debug.WriteLine("[DEBUG] memory scan completed. (time:" + DateTime.Now.ToString("h:mm:ss tt") + ")");
				return (from c in bagResult.ToList<long>()
				orderby c
				select c).AsEnumerable<long>();
			});
		}

		// Token: 0x0600006A RID: 106 RVA: 0x00004D24 File Offset: 0x00002F24
		[DebuggerStepThrough]
		public Task<long> AoBScan(string code, long end, string search)
		{
			Form1.<AoBScan>d__170 <AoBScan>d__ = new Form1.<AoBScan>d__170();
			<AoBScan>d__.<>t__builder = AsyncTaskMethodBuilder<long>.Create();
			<AoBScan>d__.<>4__this = this;
			<AoBScan>d__.code = code;
			<AoBScan>d__.end = end;
			<AoBScan>d__.search = search;
			<AoBScan>d__.<>1__state = -1;
			<AoBScan>d__.<>t__builder.Start<Form1.<AoBScan>d__170>(ref <AoBScan>d__);
			return <AoBScan>d__.<>t__builder.Task;
		}

		// Token: 0x0600006B RID: 107 RVA: 0x00004D80 File Offset: 0x00002F80
		private unsafe long[] CompareScan(Form1.MemoryRegionResult item, byte[] aobPattern, byte[] mask)
		{
			bool flag = mask.Length != aobPattern.Length;
			if (flag)
			{
				throw new ArgumentException("aobPattern.Length != mask.Length");
			}
			IntPtr intPtr = Marshal.AllocHGlobal((int)item.RegionSize);
			ulong num;
			Form1.ReadProcessMemory(this.pHandle, item.CurrentBaseAddress, intPtr, (UIntPtr)((ulong)item.RegionSize), out num);
			int num2 = -aobPattern.Length;
			List<long> list = new List<long>();
			do
			{
				num2 = this.FindPattern((byte*)intPtr.ToPointer(), (int)num, aobPattern, mask, num2 + aobPattern.Length);
				bool flag2 = num2 >= 0;
				if (flag2)
				{
					list.Add((long)((ulong)item.CurrentBaseAddress + (ulong)((long)num2)));
				}
			}
			while (num2 != -1);
			Marshal.FreeHGlobal(intPtr);
			return list.ToArray();
		}

		// Token: 0x0600006C RID: 108 RVA: 0x00004E44 File Offset: 0x00003044
		private int FindPattern(byte[] body, byte[] pattern, byte[] masks, int start = 0)
		{
			int num = -1;
			bool flag = body.Length == 0 || pattern.Length == 0 || start > body.Length - pattern.Length || pattern.Length > body.Length;
			int result;
			if (flag)
			{
				result = num;
			}
			else
			{
				for (int i = start; i <= body.Length - pattern.Length; i++)
				{
					bool flag2 = (body[i] & masks[0]) != (pattern[0] & masks[0]);
					if (!flag2)
					{
						bool flag3 = true;
						for (int j = 1; j <= pattern.Length - 1; j++)
						{
							bool flag4 = (body[i + j] & masks[j]) != (pattern[j] & masks[j]);
							if (flag4)
							{
								flag3 = false;
								break;
							}
						}
						bool flag5 = flag3;
						if (flag5)
						{
							num = i;
							break;
						}
					}
				}
				result = num;
			}
			return result;
		}

		// Token: 0x0600006D RID: 109 RVA: 0x00004F14 File Offset: 0x00003114
		private unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0)
		{
			int num = -1;
			bool flag = bodyLength <= 0 || pattern.Length == 0 || start > bodyLength - pattern.Length || pattern.Length > bodyLength;
			int result;
			if (flag)
			{
				result = num;
			}
			else
			{
				for (int i = start; i <= bodyLength - pattern.Length; i++)
				{
					bool flag2 = (body[i] & masks[0]) != (pattern[0] & masks[0]);
					if (!flag2)
					{
						bool flag3 = true;
						for (int j = 1; j <= pattern.Length - 1; j++)
						{
							bool flag4 = (body[i + j] & masks[j]) != (pattern[j] & masks[j]);
							if (flag4)
							{
								flag3 = false;
								break;
							}
						}
						bool flag5 = flag3;
						if (flag5)
						{
							num = i;
							break;
						}
					}
				}
				result = num;
			}
			return result;
		}

		// Token: 0x0600006E RID: 110 RVA: 0x00004FE4 File Offset: 0x000031E4
		private IntPtr CPUScan()
		{
			IntPtr intPtr = IntPtr.Zero;
			uint num = 0U;
			IntPtr intPtr2 = Form1.CreateToolhelp32Snapshot(2U, 0U);
			bool flag = (int)intPtr2 > 0;
			if (flag)
			{
				Form1.ProcessEntry32 processEntry = default(Form1.ProcessEntry32);
				processEntry.dwSize = (uint)Marshal.SizeOf<Form1.ProcessEntry32>(processEntry);
				for (int num2 = Form1.Process32First(intPtr2, ref processEntry); num2 == 1; num2 = Form1.Process32Next(intPtr2, ref processEntry))
				{
					IntPtr intPtr3 = Marshal.AllocHGlobal((int)processEntry.dwSize);
					Marshal.StructureToPtr<Form1.ProcessEntry32>(processEntry, intPtr3, true);
					Form1.ProcessEntry32 processEntry2 = (Form1.ProcessEntry32)Marshal.PtrToStructure(intPtr3, typeof(Form1.ProcessEntry32));
					Marshal.FreeHGlobal(intPtr3);
					bool flag2 = processEntry2.szExeFile.Contains(this.Procname) && processEntry2.cntThreads > num;
					if (flag2)
					{
						num = processEntry2.cntThreads;
						intPtr = (IntPtr)((long)((ulong)processEntry2.th32ProcessID));
					}
				}
				this.txtProc = Convert.ToString(intPtr);
				long workingSet = Process.GetProcessById(Convert.ToInt32(this.txtProc)).WorkingSet64;
				bool flag3 = workingSet > 314572800L;
				if (flag3)
				{
					this.label4.Text = "Proc ID Got";
					Form1.CloseHandle(this.pHandle);
					this.pHandle = IntPtr.Zero;
					this.pHandle = Form1.OpenProcess(65535U, false, Convert.ToInt32(this.txtProc));
					bool flag4 = this.pHandle == IntPtr.Zero;
					if (flag4)
					{
						MessageBox.Show("Load Driver Manuel!!");
					}
					this.label4.Text = "Proc ID Got";
					this.label4.Text = "Wait 1st";
					int num3 = this.ReadInt("0xE0C36E8", "");
					bool flag5 = num3 != 0;
					if (flag5)
					{
						this.ue4base = num3.ToString("X");
					}
					int num4 = this.ReadInt("0xE0C1228", "");
					bool flag6 = num4 != 0;
					if (flag6)
					{
						this.anogs = num4.ToString("X");
					}
					int num5 = this.ReadInt("0xE0C0928", "");
					bool flag7 = num5 != 0;
					if (flag7)
					{
						this.tprt = num5.ToString("X");
					}
					int num6 = this.ReadInt("0xE0C3FE8", "");
					bool flag8 = num6 != 0;
					if (flag8)
					{
						this.cubehawk = num6.ToString("X");
					}
					int num7 = this.ReadInt("0xE0C10A8", "");
					bool flag9 = num7 != 0;
					if (flag9)
					{
						this.gcloud = num7.ToString("X");
					}
					int num8 = this.ReadInt("0xE0C0F28", "");
					bool flag10 = num8 != 0;
					if (flag10)
					{
						this.tdata = num8.ToString("X");
					}
					byte[] array = this.ReadBytes(this.ue4base, 117440512L);
					byte[] array2 = this.ReadBytes(this.anogs, 3981712L);
					byte[] array3 = this.ReadBytes(this.tprt, 480472L);
					byte[] array4 = this.ReadBytes(this.cubehawk, 875836L);
					byte[] array5 = this.ReadBytes(this.gcloud, 3626148L);
					byte[] array6 = this.ReadBytes(this.tdata, 2487456L);
					bool flag11 = array != null;
					if (flag11)
					{
						File.WriteAllBytes("moded\\libUE4.so", array);
					}
					bool flag12 = array2 != null;
					if (flag12)
					{
						File.WriteAllBytes("moded\\libanogs.so", array2);
					}
					bool flag13 = array3 != null;
					if (flag13)
					{
						File.WriteAllBytes("moded\\libtprt.so", array3);
					}
					bool flag14 = array4 != null;
					if (flag14)
					{
						File.WriteAllBytes("moded\\libcubehawk.so", array4);
					}
					bool flag15 = array5 != null;
					if (flag15)
					{
						File.WriteAllBytes("moded\\libgcloud.so", array5);
					}
					bool flag16 = array6 != null;
					if (flag16)
					{
						File.WriteAllBytes("moded\\libTDataMaster.so", array6);
					}
					this.label4.Text = "Finished 1st";
				}
				else
				{
					this.CPUScan();
				}
			}
			return intPtr;
		}

		// Token: 0x0600006F RID: 111 RVA: 0x000053F0 File Offset: 0x000035F0
		private IntPtr CPUScan2()
		{
			IntPtr intPtr = IntPtr.Zero;
			uint num = 0U;
			IntPtr intPtr2 = Form1.CreateToolhelp32Snapshot(2U, 0U);
			bool flag = (int)intPtr2 > 0;
			if (flag)
			{
				Form1.ProcessEntry32 processEntry = default(Form1.ProcessEntry32);
				processEntry.dwSize = (uint)Marshal.SizeOf<Form1.ProcessEntry32>(processEntry);
				for (int num2 = Form1.Process32First(intPtr2, ref processEntry); num2 == 1; num2 = Form1.Process32Next(intPtr2, ref processEntry))
				{
					IntPtr intPtr3 = Marshal.AllocHGlobal((int)processEntry.dwSize);
					Marshal.StructureToPtr<Form1.ProcessEntry32>(processEntry, intPtr3, true);
					Form1.ProcessEntry32 processEntry2 = (Form1.ProcessEntry32)Marshal.PtrToStructure(intPtr3, typeof(Form1.ProcessEntry32));
					Marshal.FreeHGlobal(intPtr3);
					bool flag2 = processEntry2.szExeFile.Contains(this.Procname) && processEntry2.cntThreads > num;
					if (flag2)
					{
						num = processEntry2.cntThreads;
						intPtr = (IntPtr)((long)((ulong)processEntry2.th32ProcessID));
					}
				}
				this.txtProc = Convert.ToString(intPtr);
				long workingSet = Process.GetProcessById(Convert.ToInt32(this.txtProc)).WorkingSet64;
				bool flag3 = workingSet > 314572800L;
				if (flag3)
				{
					this.label4.Text = "Proc ID Got";
					Form1.CloseHandle(this.pHandle);
					this.pHandle = IntPtr.Zero;
					this.pHandle = Form1.OpenProcess(65535U, false, Convert.ToInt32(this.txtProc));
					bool flag4 = this.pHandle == IntPtr.Zero;
					if (flag4)
					{
						MessageBox.Show("Load Driver Manuel!!");
					}
					this.label4.Text = "Proc ID Got";
					this.label4.Text = "Wait 2nd";
					int num3 = this.ReadInt("0xE0C36E8", "");
					bool flag5 = num3 != 0;
					if (flag5)
					{
						this.ue4base = num3.ToString("X");
					}
					int num4 = this.ReadInt("0xE0C1228", "");
					bool flag6 = num4 != 0;
					if (flag6)
					{
						this.anogs = num4.ToString("X");
					}
					int num5 = this.ReadInt("0xE0C0928", "");
					bool flag7 = num5 != 0;
					if (flag7)
					{
						this.tprt = num5.ToString("X");
					}
					int num6 = this.ReadInt("0xE0C3FE8", "");
					bool flag8 = num6 != 0;
					if (flag8)
					{
						this.cubehawk = num6.ToString("X");
					}
					int num7 = this.ReadInt("0xE0C10A8", "");
					bool flag9 = num7 != 0;
					if (flag9)
					{
						this.gcloud = num7.ToString("X");
					}
					int num8 = this.ReadInt("0xE0C0F28", "");
					bool flag10 = num8 != 0;
					if (flag10)
					{
						this.tdata = num8.ToString("X");
					}
					byte[] array = this.ReadBytes(this.ue4base, 117440512L);
					byte[] array2 = this.ReadBytes(this.anogs, 3981712L);
					byte[] array3 = this.ReadBytes(this.tprt, 480472L);
					byte[] array4 = this.ReadBytes(this.cubehawk, 875836L);
					byte[] array5 = this.ReadBytes(this.gcloud, 3626148L);
					byte[] array6 = this.ReadBytes(this.tdata, 2487456L);
					bool flag11 = array != null;
					if (flag11)
					{
						File.WriteAllBytes("orginal\\libUE4.so", array);
					}
					bool flag12 = array2 != null;
					if (flag12)
					{
						File.WriteAllBytes("orginal\\libanogs.so", array2);
					}
					bool flag13 = array3 != null;
					if (flag13)
					{
						File.WriteAllBytes("orginal\\libtprt.so", array3);
					}
					bool flag14 = array4 != null;
					if (flag14)
					{
						File.WriteAllBytes("orginal\\libcubehawk.so", array4);
					}
					bool flag15 = array5 != null;
					if (flag15)
					{
						File.WriteAllBytes("orginal\\libgcloud.so", array5);
					}
					bool flag16 = array6 != null;
					if (flag16)
					{
						File.WriteAllBytes("orginal\\libTDataMaster.so", array6);
					}
					this.label4.Text = "Finished 2nd";
				}
				else
				{
					this.CPUScan();
				}
			}
			return intPtr;
		}

		// Token: 0x06000070 RID: 112 RVA: 0x000057FA File Offset: 0x000039FA
		private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x06000071 RID: 113 RVA: 0x000057FD File Offset: 0x000039FD
		private void label1_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000072 RID: 114 RVA: 0x00005800 File Offset: 0x00003A00
		private void button1_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000073 RID: 115 RVA: 0x00005803 File Offset: 0x00003A03
		private void button2_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000074 RID: 116 RVA: 0x00005806 File Offset: 0x00003A06
		private void button3_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000075 RID: 117 RVA: 0x00005809 File Offset: 0x00003A09
		private void button4_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000076 RID: 118 RVA: 0x0000580C File Offset: 0x00003A0C
		private void button5_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000077 RID: 119 RVA: 0x0000580F File Offset: 0x00003A0F
		private void MainMenu_ItemClicked(object sender, ToolStripItemClickedEventArgs e)
		{
		}

		// Token: 0x06000078 RID: 120 RVA: 0x00005812 File Offset: 0x00003A12
		private void OriginalOpen_FileOk(object sender, CancelEventArgs e)
		{
		}

		// Token: 0x06000079 RID: 121 RVA: 0x00005815 File Offset: 0x00003A15
		private void DumpOpen_FileOk(object sender, CancelEventArgs e)
		{
		}

		// Token: 0x0600007A RID: 122 RVA: 0x00005818 File Offset: 0x00003A18
		private void menuStrip1_ItemClicked(object sender, ToolStripItemClickedEventArgs e)
		{
		}

		// Token: 0x0600007B RID: 123 RVA: 0x0000581B File Offset: 0x00003A1B
		private void bProcess_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600007C RID: 124 RVA: 0x0000581E File Offset: 0x00003A1E
		private void tbDump_TextChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x0600007D RID: 125 RVA: 0x00005821 File Offset: 0x00003A21
		private void fileToolStripMenuItem_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600007E RID: 126 RVA: 0x00005824 File Offset: 0x00003A24
		[DebuggerStepThrough]
		private void metroButton2_Click(object sender, EventArgs e)
		{
			Form1.<metroButton2_Click>d__190 <metroButton2_Click>d__ = new Form1.<metroButton2_Click>d__190();
			<metroButton2_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<metroButton2_Click>d__.<>4__this = this;
			<metroButton2_Click>d__.sender = sender;
			<metroButton2_Click>d__.e = e;
			<metroButton2_Click>d__.<>1__state = -1;
			<metroButton2_Click>d__.<>t__builder.Start<Form1.<metroButton2_Click>d__190>(ref <metroButton2_Click>d__);
		}

		// Token: 0x0600007F RID: 127 RVA: 0x0000586B File Offset: 0x00003A6B
		private void labOffset_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000080 RID: 128 RVA: 0x0000586E File Offset: 0x00003A6E
		private void metroLabel1_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000081 RID: 129 RVA: 0x00005871 File Offset: 0x00003A71
		private void metroTextBox1_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000082 RID: 130 RVA: 0x00005874 File Offset: 0x00003A74
		private void tbOriginal_TextChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x06000083 RID: 131 RVA: 0x00005877 File Offset: 0x00003A77
		private void metroTextBox2_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000084 RID: 132 RVA: 0x0000587A File Offset: 0x00003A7A
		private void metroComboBox1_SelectedIndexChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x06000085 RID: 133 RVA: 0x0000587D File Offset: 0x00003A7D
		private void label2_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000086 RID: 134 RVA: 0x00005880 File Offset: 0x00003A80
		private void metroLabel2_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000087 RID: 135 RVA: 0x00005884 File Offset: 0x00003A84
		private void metroButton1_Click(object sender, EventArgs e)
		{
			bool flag = !File.Exists("C:\\AV.sys");
			if (flag)
			{
				File.WriteAllBytes("C:\\AV.sys", Form1.driver);
			}
			Form1.RunCMD("sc create AV binPath=C:\\AV.sys type=kernel", false, true, false);
			Form1.RunCMD("net start AV", false, true, false);
			this.label4.Text = "Driver Loaded";
		}

		// Token: 0x06000088 RID: 136 RVA: 0x000058E2 File Offset: 0x00003AE2
		private void metroButton3_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000089 RID: 137 RVA: 0x000058E5 File Offset: 0x00003AE5
		private void metroButton5_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600008A RID: 138 RVA: 0x000058E8 File Offset: 0x00003AE8
		private void metroButton6_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600008B RID: 139 RVA: 0x000058EB File Offset: 0x00003AEB
		private void metroButton4_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600008C RID: 140 RVA: 0x000058EE File Offset: 0x00003AEE
		private void metroToolTip1_Popup(object sender, PopupEventArgs e)
		{
		}

		// Token: 0x0600008D RID: 141 RVA: 0x000058F1 File Offset: 0x00003AF1
		private void metroTextBox3_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600008E RID: 142 RVA: 0x000058F4 File Offset: 0x00003AF4
		private void metroCheckBox1_CheckedChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x0600008F RID: 143 RVA: 0x000058F7 File Offset: 0x00003AF7
		private void siticoneCheckBox1_CheckedChanged_1(object sender, EventArgs e)
		{
		}

		// Token: 0x06000090 RID: 144 RVA: 0x000058FC File Offset: 0x00003AFC
		[DebuggerStepThrough]
		private void metroButton7_Click_1(object sender, EventArgs e)
		{
			Form1.<metroButton7_Click_1>d__208 <metroButton7_Click_1>d__ = new Form1.<metroButton7_Click_1>d__208();
			<metroButton7_Click_1>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<metroButton7_Click_1>d__.<>4__this = this;
			<metroButton7_Click_1>d__.sender = sender;
			<metroButton7_Click_1>d__.e = e;
			<metroButton7_Click_1>d__.<>1__state = -1;
			<metroButton7_Click_1>d__.<>t__builder.Start<Form1.<metroButton7_Click_1>d__208>(ref <metroButton7_Click_1>d__);
		}

		// Token: 0x06000091 RID: 145 RVA: 0x00005943 File Offset: 0x00003B43
		private void groupBox2_Enter(object sender, EventArgs e)
		{
		}

		// Token: 0x06000092 RID: 146 RVA: 0x00005946 File Offset: 0x00003B46
		private void metroButton8_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000093 RID: 147 RVA: 0x00005949 File Offset: 0x00003B49
		private void Worker_DoWork(object sender, DoWorkEventArgs e)
		{
		}

		// Token: 0x06000094 RID: 148 RVA: 0x0000594C File Offset: 0x00003B4C
		private void bunifuButton1_Click(object sender, EventArgs e)
		{
			bool flag = !File.Exists("C:\\AV.sys");
			if (flag)
			{
				File.WriteAllBytes("C:\\AV.sys", Form1.driver);
			}
			Form1.RunCMD("sc create AV binPath=C:\\AV.sys type=kernel", false, true, false);
			Form1.RunCMD("net start AV", false, true, false);
			this.label4.Text = "Driver Loaded";
		}

		// Token: 0x06000095 RID: 149 RVA: 0x000059AA File Offset: 0x00003BAA
		private void bunifuButton5_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000096 RID: 150 RVA: 0x000059AD File Offset: 0x00003BAD
		private void bunifuButton3_Click(object sender, EventArgs e)
		{
			Form1.RunCMD("net stop AV", false, true, false);
			Form1.RunCMD("sc delete AV", false, true, false);
			File.Delete("C:\\AV.sys");
			this.label4.Text = "Driver Unloaded";
		}

		// Token: 0x06000097 RID: 151 RVA: 0x000059E8 File Offset: 0x00003BE8
		private void bunifuButton4_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000098 RID: 152 RVA: 0x000059EB File Offset: 0x00003BEB
		private void bunifuButton2_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x06000099 RID: 153 RVA: 0x000059EE File Offset: 0x00003BEE
		private void bunifuButton6_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600009A RID: 154 RVA: 0x000059F1 File Offset: 0x00003BF1
		private void bunifuButton7_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600009B RID: 155 RVA: 0x000059F4 File Offset: 0x00003BF4
		private void label3_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600009C RID: 156 RVA: 0x000059F7 File Offset: 0x00003BF7
		private void label4_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x0600009D RID: 157 RVA: 0x000059FA File Offset: 0x00003BFA
		private void bunifuTextBox1_TextChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x0600009E RID: 158 RVA: 0x000059FD File Offset: 0x00003BFD
		private void bunifuTextBox2_TextChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x0600009F RID: 159 RVA: 0x00005A00 File Offset: 0x00003C00
		private void bunifuTextBox3_TextChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A0 RID: 160 RVA: 0x00005A03 File Offset: 0x00003C03
		private void groupBox1_Enter(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A1 RID: 161 RVA: 0x00005A08 File Offset: 0x00003C08
		[DebuggerStepThrough]
		private void bunifuButton8_Click(object sender, EventArgs e)
		{
			Form1.<bunifuButton8_Click>d__225 <bunifuButton8_Click>d__ = new Form1.<bunifuButton8_Click>d__225();
			<bunifuButton8_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<bunifuButton8_Click>d__.<>4__this = this;
			<bunifuButton8_Click>d__.sender = sender;
			<bunifuButton8_Click>d__.e = e;
			<bunifuButton8_Click>d__.<>1__state = -1;
			<bunifuButton8_Click>d__.<>t__builder.Start<Form1.<bunifuButton8_Click>d__225>(ref <bunifuButton8_Click>d__);
		}

		// Token: 0x060000A2 RID: 162 RVA: 0x00005A4F File Offset: 0x00003C4F
		private void label5_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A3 RID: 163 RVA: 0x00005A52 File Offset: 0x00003C52
		private void comboBox1_SelectedIndexChanged_1(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A4 RID: 164 RVA: 0x00005A55 File Offset: 0x00003C55
		private void siticoneRoundedComboBox1_SelectedIndexChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A5 RID: 165 RVA: 0x00005A58 File Offset: 0x00003C58
		private void bunifuLabel1_Click(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A6 RID: 166 RVA: 0x00005A5B File Offset: 0x00003C5B
		private void guna2ToggleSwitch1_CheckedChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A7 RID: 167 RVA: 0x00005A5E File Offset: 0x00003C5E
		private void bunifuButton6_Click_1(object sender, EventArgs e)
		{
		}

		// Token: 0x060000A8 RID: 168 RVA: 0x00005A61 File Offset: 0x00003C61
		private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
		{
		}

		// Token: 0x060000A9 RID: 169 RVA: 0x00005A64 File Offset: 0x00003C64
		[DebuggerStepThrough]
		private void siticoneRoundedGradientButton1_Click(object sender, EventArgs e)
		{
			Form1.<siticoneRoundedGradientButton1_Click>d__233 <siticoneRoundedGradientButton1_Click>d__ = new Form1.<siticoneRoundedGradientButton1_Click>d__233();
			<siticoneRoundedGradientButton1_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<siticoneRoundedGradientButton1_Click>d__.<>4__this = this;
			<siticoneRoundedGradientButton1_Click>d__.sender = sender;
			<siticoneRoundedGradientButton1_Click>d__.e = e;
			<siticoneRoundedGradientButton1_Click>d__.<>1__state = -1;
			<siticoneRoundedGradientButton1_Click>d__.<>t__builder.Start<Form1.<siticoneRoundedGradientButton1_Click>d__233>(ref <siticoneRoundedGradientButton1_Click>d__);
		}

		// Token: 0x060000AA RID: 170 RVA: 0x00005AAC File Offset: 0x00003CAC
		[DebuggerStepThrough]
		private void siticoneRoundedGradientButton2_Click(object sender, EventArgs e)
		{
			Form1.<siticoneRoundedGradientButton2_Click>d__234 <siticoneRoundedGradientButton2_Click>d__ = new Form1.<siticoneRoundedGradientButton2_Click>d__234();
			<siticoneRoundedGradientButton2_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<siticoneRoundedGradientButton2_Click>d__.<>4__this = this;
			<siticoneRoundedGradientButton2_Click>d__.sender = sender;
			<siticoneRoundedGradientButton2_Click>d__.e = e;
			<siticoneRoundedGradientButton2_Click>d__.<>1__state = -1;
			<siticoneRoundedGradientButton2_Click>d__.<>t__builder.Start<Form1.<siticoneRoundedGradientButton2_Click>d__234>(ref <siticoneRoundedGradientButton2_Click>d__);
		}

		// Token: 0x060000AB RID: 171 RVA: 0x00005AF4 File Offset: 0x00003CF4
		[DebuggerStepThrough]
		private void siticoneRoundedGradientButton3_Click(object sender, EventArgs e)
		{
			Form1.<siticoneRoundedGradientButton3_Click>d__235 <siticoneRoundedGradientButton3_Click>d__ = new Form1.<siticoneRoundedGradientButton3_Click>d__235();
			<siticoneRoundedGradientButton3_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<siticoneRoundedGradientButton3_Click>d__.<>4__this = this;
			<siticoneRoundedGradientButton3_Click>d__.sender = sender;
			<siticoneRoundedGradientButton3_Click>d__.e = e;
			<siticoneRoundedGradientButton3_Click>d__.<>1__state = -1;
			<siticoneRoundedGradientButton3_Click>d__.<>t__builder.Start<Form1.<siticoneRoundedGradientButton3_Click>d__235>(ref <siticoneRoundedGradientButton3_Click>d__);
		}

		// Token: 0x060000AC RID: 172 RVA: 0x00005B3C File Offset: 0x00003D3C
		[DebuggerStepThrough]
		private void siticoneRoundedGradientButton4_Click(object sender, EventArgs e)
		{
			Form1.<siticoneRoundedGradientButton4_Click>d__236 <siticoneRoundedGradientButton4_Click>d__ = new Form1.<siticoneRoundedGradientButton4_Click>d__236();
			<siticoneRoundedGradientButton4_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<siticoneRoundedGradientButton4_Click>d__.<>4__this = this;
			<siticoneRoundedGradientButton4_Click>d__.sender = sender;
			<siticoneRoundedGradientButton4_Click>d__.e = e;
			<siticoneRoundedGradientButton4_Click>d__.<>1__state = -1;
			<siticoneRoundedGradientButton4_Click>d__.<>t__builder.Start<Form1.<siticoneRoundedGradientButton4_Click>d__236>(ref <siticoneRoundedGradientButton4_Click>d__);
		}

		// Token: 0x060000AD RID: 173 RVA: 0x00005B84 File Offset: 0x00003D84
		[DebuggerStepThrough]
		private void def()
		{
			Form1.<def>d__237 <def>d__ = new Form1.<def>d__237();
			<def>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<def>d__.<>4__this = this;
			<def>d__.<>1__state = -1;
			<def>d__.<>t__builder.Start<Form1.<def>d__237>(ref <def>d__);
		}

		// Token: 0x060000AE RID: 174 RVA: 0x00005BC0 File Offset: 0x00003DC0
		[DebuggerStepThrough]
		private void siticoneRoundedGradientButton5_Click(object sender, EventArgs e)
		{
			Form1.<siticoneRoundedGradientButton5_Click>d__238 <siticoneRoundedGradientButton5_Click>d__ = new Form1.<siticoneRoundedGradientButton5_Click>d__238();
			<siticoneRoundedGradientButton5_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<siticoneRoundedGradientButton5_Click>d__.<>4__this = this;
			<siticoneRoundedGradientButton5_Click>d__.sender = sender;
			<siticoneRoundedGradientButton5_Click>d__.e = e;
			<siticoneRoundedGradientButton5_Click>d__.<>1__state = -1;
			<siticoneRoundedGradientButton5_Click>d__.<>t__builder.Start<Form1.<siticoneRoundedGradientButton5_Click>d__238>(ref <siticoneRoundedGradientButton5_Click>d__);
		}

		// Token: 0x060000AF RID: 175 RVA: 0x00005C07 File Offset: 0x00003E07
		private void label1_Click_1(object sender, EventArgs e)
		{
		}

		// Token: 0x060000B0 RID: 176 RVA: 0x00005C0A File Offset: 0x00003E0A
		private void backgroundWorker2_DoWork(object sender, DoWorkEventArgs e)
		{
		}

		// Token: 0x060000B1 RID: 177 RVA: 0x00005C0D File Offset: 0x00003E0D
		private void bunifuTextBox4_TextChanged(object sender, EventArgs e)
		{
		}

		// Token: 0x060000B2 RID: 178 RVA: 0x00005C10 File Offset: 0x00003E10
		private void siticoneRoundedGradientButton1_Click_1(object sender, EventArgs e)
		{
			bool flag = !File.Exists("C:\\AV.sys");
			if (flag)
			{
				File.WriteAllBytes("C:\\AV.sys", Form1.driver);
			}
			Form1.RunCMD("sc create AV binPath=C:\\AV.sys type=kernel", false, true, false);
			Form1.RunCMD("net start AV", false, true, false);
			this.label4.Text = "Loaded";
		}

		// Token: 0x060000B3 RID: 179 RVA: 0x00005C70 File Offset: 0x00003E70
		private void siticoneRoundedGradientButton2_Click_1(object sender, EventArgs e)
		{
			Form1.RunCMD("net stop AV", false, true, false);
			Form1.RunCMD("sc delete AV", false, true, false);
			bool flag = File.Exists("C:\\AV.sys");
			if (flag)
			{
				File.Delete("C:\\AV.sys");
			}
			this.label4.Text = "Unloaded";
		}

		// Token: 0x060000B4 RID: 180 RVA: 0x00005CC8 File Offset: 0x00003EC8
		[DebuggerStepThrough]
		private void siticoneRoundedGradientButton6_Click(object sender, EventArgs e)
		{
			Form1.<siticoneRoundedGradientButton6_Click>d__244 <siticoneRoundedGradientButton6_Click>d__ = new Form1.<siticoneRoundedGradientButton6_Click>d__244();
			<siticoneRoundedGradientButton6_Click>d__.<>t__builder = AsyncVoidMethodBuilder.Create();
			<siticoneRoundedGradientButton6_Click>d__.<>4__this = this;
			<siticoneRoundedGradientButton6_Click>d__.sender = sender;
			<siticoneRoundedGradientButton6_Click>d__.e = e;
			<siticoneRoundedGradientButton6_Click>d__.<>1__state = -1;
			<siticoneRoundedGradientButton6_Click>d__.<>t__builder.Start<Form1.<siticoneRoundedGradientButton6_Click>d__244>(ref <siticoneRoundedGradientButton6_Click>d__);
		}

		// Token: 0x04000004 RID: 4
		private string ipconfigOutput;

		// Token: 0x04000005 RID: 5
		private string processnamestr;

		// Token: 0x04000006 RID: 6
		private string ue4base;

		// Token: 0x04000007 RID: 7
		private string anogs;

		// Token: 0x04000008 RID: 8
		private string tdata;

		// Token: 0x04000009 RID: 9
		private string gcloud;

		// Token: 0x0400000A RID: 10
		private string tprt;

		// Token: 0x0400000B RID: 11
		private string Bugly;

		// Token: 0x0400000C RID: 12
		private string cubehawk;

		// Token: 0x0400000D RID: 13
		private string tgpa;

		// Token: 0x0400000E RID: 14
		private string dumpFile = "";

		// Token: 0x0400000F RID: 15
		private string origFile = "";

		// Token: 0x04000010 RID: 16
		private long counter;

		// Token: 0x04000011 RID: 17
		public int TargetMemory = 250;

		// Token: 0x04000012 RID: 18
		private bool valver;

		// Token: 0x04000013 RID: 19
		private long libUE4Base;

		// Token: 0x04000014 RID: 20
		private long loadstat;

		// Token: 0x04000015 RID: 21
		private bool loadinfo;

		// Token: 0x04000016 RID: 22
		public long libtersafeBase;

		// Token: 0x04000017 RID: 23
		private string txtProc;

		// Token: 0x04000018 RID: 24
		private string Procname;

		// Token: 0x04000019 RID: 25
		private SaveFileDialog saveUI = new SaveFileDialog();

		// Token: 0x0400001A RID: 26
		private long num1;

		// Token: 0x0400001B RID: 27
		private long num2;

		// Token: 0x0400001C RID: 28
		private string processemu;

		// Token: 0x0400001D RID: 29
		public long libgcloud;

		// Token: 0x0400001E RID: 30
		public long libanogs;

		// Token: 0x0400001F RID: 31
		public long libBugly;

		// Token: 0x04000020 RID: 32
		public long libcubehawk;

		// Token: 0x04000021 RID: 33
		public long libtgpa;

		// Token: 0x04000022 RID: 34
		public long libtprt;

		// Token: 0x04000023 RID: 35
		public long libTDataMaster;

		// Token: 0x04000024 RID: 36
		private static byte[] driver = new byte[]
		{
			77,
			90,
			144,
			0,
			3,
			0,
			0,
			0,
			4,
			0,
			0,
			0,
			byte.MaxValue,
			byte.MaxValue,
			0,
			0,
			184,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			240,
			0,
			0,
			0,
			14,
			31,
			186,
			14,
			0,
			180,
			9,
			205,
			33,
			184,
			1,
			76,
			205,
			33,
			84,
			104,
			105,
			115,
			32,
			112,
			114,
			111,
			103,
			114,
			97,
			109,
			32,
			99,
			97,
			110,
			110,
			111,
			116,
			32,
			98,
			101,
			32,
			114,
			117,
			110,
			32,
			105,
			110,
			32,
			68,
			79,
			83,
			32,
			109,
			111,
			100,
			101,
			46,
			13,
			13,
			10,
			36,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			93,
			51,
			89,
			224,
			25,
			82,
			55,
			179,
			25,
			82,
			55,
			179,
			25,
			82,
			55,
			179,
			16,
			42,
			191,
			179,
			26,
			82,
			55,
			179,
			16,
			42,
			164,
			179,
			27,
			82,
			55,
			179,
			25,
			82,
			54,
			179,
			18,
			82,
			55,
			179,
			59,
			50,
			54,
			178,
			26,
			82,
			55,
			179,
			59,
			50,
			52,
			178,
			26,
			82,
			55,
			179,
			59,
			50,
			51,
			178,
			26,
			82,
			55,
			179,
			142,
			12,
			51,
			178,
			24,
			82,
			55,
			179,
			142,
			12,
			53,
			178,
			24,
			82,
			55,
			179,
			82,
			105,
			99,
			104,
			25,
			82,
			55,
			179,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			80,
			69,
			0,
			0,
			100,
			134,
			7,
			0,
			203,
			15,
			43,
			91,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			240,
			0,
			34,
			0,
			11,
			2,
			14,
			0,
			0,
			12,
			0,
			0,
			0,
			28,
			0,
			0,
			0,
			0,
			0,
			0,
			132,
			17,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			0,
			0,
			64,
			1,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			2,
			0,
			0,
			10,
			0,
			0,
			0,
			10,
			0,
			0,
			0,
			6,
			0,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			128,
			0,
			0,
			0,
			4,
			0,
			0,
			217,
			97,
			0,
			0,
			1,
			0,
			96,
			1,
			0,
			0,
			16,
			0,
			0,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			100,
			96,
			0,
			0,
			60,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			180,
			0,
			0,
			0,
			0,
			30,
			0,
			0,
			112,
			17,
			0,
			0,
			0,
			112,
			0,
			0,
			40,
			0,
			0,
			0,
			176,
			32,
			0,
			0,
			56,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			240,
			32,
			0,
			0,
			244,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			32,
			0,
			0,
			104,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			46,
			116,
			101,
			120,
			116,
			0,
			0,
			0,
			9,
			7,
			0,
			0,
			0,
			16,
			0,
			0,
			0,
			8,
			0,
			0,
			0,
			4,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			32,
			0,
			0,
			104,
			46,
			114,
			100,
			97,
			116,
			97,
			0,
			0,
			160,
			4,
			0,
			0,
			0,
			32,
			0,
			0,
			0,
			6,
			0,
			0,
			0,
			12,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			72,
			46,
			100,
			97,
			116,
			97,
			0,
			0,
			0,
			56,
			15,
			0,
			0,
			0,
			48,
			0,
			0,
			0,
			2,
			0,
			0,
			0,
			18,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			200,
			46,
			112,
			100,
			97,
			116,
			97,
			0,
			0,
			180,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			0,
			2,
			0,
			0,
			0,
			20,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			72,
			46,
			103,
			102,
			105,
			100,
			115,
			0,
			0,
			4,
			0,
			0,
			0,
			0,
			80,
			0,
			0,
			0,
			2,
			0,
			0,
			0,
			22,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			72,
			73,
			78,
			73,
			84,
			0,
			0,
			0,
			0,
			6,
			2,
			0,
			0,
			0,
			96,
			0,
			0,
			0,
			4,
			0,
			0,
			0,
			24,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			32,
			0,
			0,
			98,
			46,
			114,
			101,
			108,
			111,
			99,
			0,
			0,
			40,
			0,
			0,
			0,
			0,
			112,
			0,
			0,
			0,
			2,
			0,
			0,
			0,
			28,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			66,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			72,
			131,
			236,
			40,
			72,
			141,
			13,
			245,
			31,
			0,
			0,
			232,
			160,
			1,
			0,
			0,
			76,
			139,
			5,
			241,
			44,
			0,
			0,
			72,
			141,
			21,
			226,
			31,
			0,
			0,
			72,
			141,
			13,
			195,
			44,
			0,
			0,
			72,
			131,
			196,
			40,
			233,
			66,
			4,
			0,
			0,
			204,
			204,
			233,
			203,
			byte.MaxValue,
			byte.MaxValue,
			byte.MaxValue,
			204,
			204,
			204,
			72,
			131,
			236,
			40,
			72,
			139,
			5,
			181,
			44,
			0,
			0,
			72,
			133,
			192,
			116,
			14,
			72,
			141,
			21,
			233,
			byte.MaxValue,
			byte.MaxValue,
			byte.MaxValue,
			72,
			59,
			194,
			116,
			2,
			byte.MaxValue,
			208,
			72,
			131,
			196,
			40,
			233,
			161,
			byte.MaxValue,
			byte.MaxValue,
			byte.MaxValue,
			204,
			72,
			137,
			92,
			36,
			8,
			72,
			137,
			108,
			36,
			16,
			72,
			137,
			116,
			36,
			24,
			87,
			72,
			131,
			236,
			32,
			51,
			237,
			72,
			139,
			242,
			72,
			139,
			249,
			72,
			59,
			205,
			117,
			12,
			51,
			201,
			232,
			152,
			2,
			0,
			0,
			233,
			224,
			0,
			0,
			0,
			184,
			8,
			2,
			0,
			0,
			72,
			137,
			13,
			119,
			44,
			0,
			0,
			72,
			141,
			13,
			72,
			44,
			0,
			0,
			102,
			137,
			5,
			67,
			44,
			0,
			0,
			72,
			141,
			5,
			114,
			44,
			0,
			0,
			102,
			137,
			45,
			51,
			44,
			0,
			0,
			72,
			137,
			5,
			52,
			44,
			0,
			0,
			byte.MaxValue,
			21,
			110,
			15,
			0,
			0,
			76,
			141,
			13,
			63,
			44,
			0,
			0,
			76,
			141,
			5,
			48,
			31,
			0,
			0,
			72,
			141,
			21,
			17,
			44,
			0,
			0,
			72,
			139,
			207,
			232,
			151,
			3,
			0,
			0,
			59,
			197,
			15,
			140,
			134,
			0,
			0,
			0,
			72,
			141,
			13,
			18,
			31,
			0,
			0,
			232,
			53,
			1,
			0,
			0,
			59,
			197,
			139,
			216,
			124,
			109,
			232,
			178,
			1,
			0,
			0,
			72,
			139,
			214,
			72,
			139,
			207,
			232,
			23,
			2,
			0,
			0,
			59,
			197,
			139,
			216,
			124,
			87,
			72,
			139,
			5,
			242,
			43,
			0,
			0,
			64,
			56,
			104,
			48,
			116,
			36,
			72,
			139,
			5,
			213,
			43,
			0,
			0,
			72,
			57,
			111,
			104,
			72,
			15,
			69,
			71,
			104,
			72,
			137,
			5,
			197,
			43,
			0,
			0,
			72,
			141,
			5,
			254,
			254,
			byte.MaxValue,
			byte.MaxValue,
			72,
			137,
			71,
			104,
			235,
			34,
			246,
			64,
			8,
			2,
			116,
			28,
			72,
			139,
			5,
			123,
			37,
			0,
			0,
			72,
			137,
			5,
			172,
			43,
			0,
			0,
			72,
			141,
			5,
			213,
			254,
			byte.MaxValue,
			byte.MaxValue,
			72,
			137,
			5,
			102,
			37,
			0,
			0,
			51,
			192,
			235,
			7,
			232,
			149,
			254,
			byte.MaxValue,
			byte.MaxValue,
			139,
			195,
			72,
			139,
			92,
			36,
			48,
			72,
			139,
			108,
			36,
			56,
			72,
			139,
			116,
			36,
			64,
			72,
			131,
			196,
			32,
			95,
			195,
			204,
			204,
			72,
			137,
			92,
			36,
			8,
			87,
			72,
			131,
			236,
			32,
			72,
			139,
			218,
			72,
			139,
			249,
			232,
			103,
			78,
			0,
			0,
			72,
			139,
			211,
			72,
			139,
			207,
			72,
			139,
			92,
			36,
			48,
			72,
			131,
			196,
			32,
			95,
			233,
			178,
			254,
			byte.MaxValue,
			byte.MaxValue,
			204,
			204,
			72,
			137,
			92,
			36,
			8,
			87,
			72,
			131,
			236,
			32,
			72,
			139,
			5,
			151,
			30,
			0,
			0,
			72,
			139,
			249,
			72,
			141,
			13,
			117,
			30,
			0,
			0,
			72,
			141,
			29,
			126,
			30,
			0,
			0,
			72,
			59,
			193,
			116,
			69,
			72,
			59,
			216,
			119,
			64,
			72,
			139,
			67,
			64,
			72,
			133,
			192,
			116,
			24,
			76,
			139,
			5,
			28,
			43,
			0,
			0,
			72,
			141,
			13,
			143,
			2,
			0,
			0,
			76,
			139,
			203,
			72,
			139,
			215,
			byte.MaxValue,
			208,
			235,
			18,
			72,
			139,
			21,
			4,
			43,
			0,
			0,
			76,
			139,
			195,
			72,
			139,
			207,
			232,
			115,
			2,
			0,
			0,
			72,
			131,
			195,
			80,
			72,
			59,
			29,
			62,
			30,
			0,
			0,
			118,
			192,
			72,
			139,
			92,
			36,
			48,
			72,
			131,
			196,
			32,
			95,
			195,
			204,
			72,
			137,
			92,
			36,
			8,
			72,
			137,
			116,
			36,
			16,
			87,
			72,
			131,
			236,
			32,
			72,
			139,
			249,
			51,
			192,
			72,
			141,
			29,
			13,
			30,
			0,
			0,
			72,
			141,
			53,
			6,
			30,
			0,
			0,
			72,
			59,
			222,
			115,
			78,
			131,
			59,
			80,
			117,
			68,
			72,
			139,
			67,
			56,
			72,
			137,
			29,
			249,
			29,
			0,
			0,
			72,
			133,
			192,
			116,
			24,
			76,
			139,
			5,
			157,
			42,
			0,
			0,
			72,
			141,
			13,
			10,
			2,
			0,
			0,
			76,
			139,
			203,
			72,
			139,
			215,
			byte.MaxValue,
			208,
			235,
			18,
			72,
			139,
			21,
			133,
			42,
			0,
			0,
			76,
			139,
			195,
			72,
			139,
			207,
			232,
			238,
			1,
			0,
			0,
			133,
			192,
			120,
			11,
			72,
			131,
			195,
			80,
			235,
			178,
			184,
			4,
			0,
			0,
			192,
			72,
			139,
			92,
			36,
			48,
			72,
			139,
			116,
			36,
			56,
			72,
			131,
			196,
			32,
			95,
			195,
			204,
			204,
			204,
			72,
			137,
			92,
			36,
			8,
			87,
			72,
			131,
			236,
			32,
			72,
			141,
			5,
			175,
			29,
			0,
			0,
			72,
			141,
			13,
			168,
			29,
			0,
			0,
			72,
			59,
			193,
			115,
			60,
			72,
			43,
			200,
			72,
			184,
			205,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			72,
			141,
			29,
			175,
			29,
			0,
			0,
			72,
			byte.MaxValue,
			201,
			72,
			247,
			225,
			72,
			139,
			250,
			72,
			193,
			239,
			5,
			72,
			byte.MaxValue,
			199,
			72,
			139,
			3,
			72,
			133,
			192,
			116,
			6,
			byte.MaxValue,
			208,
			72,
			137,
			67,
			248,
			72,
			131,
			195,
			40,
			72,
			131,
			239,
			1,
			117,
			232,
			72,
			139,
			92,
			36,
			48,
			72,
			131,
			196,
			32,
			95,
			195,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			72,
			137,
			92,
			36,
			8,
			85,
			72,
			139,
			236,
			72,
			131,
			236,
			112,
			72,
			141,
			5,
			0,
			1,
			0,
			0,
			72,
			139,
			217,
			72,
			137,
			65,
			104,
			72,
			141,
			13,
			62,
			3,
			0,
			0,
			232,
			25,
			1,
			0,
			0,
			72,
			139,
			67,
			40,
			72,
			141,
			77,
			208,
			51,
			210,
			131,
			72,
			104,
			32,
			68,
			141,
			66,
			40,
			232,
			34,
			2,
			0,
			0,
			byte.MaxValue,
			21,
			196,
			12,
			0,
			0,
			72,
			131,
			101,
			232,
			0,
			72,
			141,
			21,
			48,
			3,
			0,
			0,
			187,
			1,
			0,
			0,
			0,
			102,
			137,
			69,
			208,
			72,
			141,
			77,
			216,
			102,
			137,
			93,
			210,
			byte.MaxValue,
			21,
			209,
			12,
			0,
			0,
			51,
			210,
			68,
			141,
			67,
			31,
			72,
			141,
			77,
			176,
			232,
			234,
			1,
			0,
			0,
			72,
			139,
			5,
			179,
			12,
			0,
			0,
			72,
			141,
			21,
			140,
			43,
			0,
			0,
			72,
			137,
			69,
			176,
			72,
			141,
			77,
			208,
			72,
			141,
			5,
			105,
			0,
			0,
			0,
			199,
			69,
			184,
			3,
			0,
			0,
			0,
			72,
			137,
			69,
			192,
			72,
			141,
			69,
			176,
			72,
			137,
			69,
			240,
			byte.MaxValue,
			21,
			116,
			12,
			0,
			0,
			133,
			192,
			117,
			39,
			72,
			141,
			13,
			217,
			2,
			0,
			0,
			232,
			132,
			0,
			0,
			0,
			72,
			139,
			21,
			77,
			43,
			0,
			0,
			72,
			141,
			13,
			230,
			2,
			0,
			0,
			232,
			113,
			0,
			0,
			0,
			137,
			29,
			51,
			43,
			0,
			0,
			235,
			21,
			139,
			208,
			72,
			141,
			13,
			224,
			2,
			0,
			0,
			232,
			91,
			0,
			0,
			0,
			131,
			37,
			28,
			43,
			0,
			0,
			0,
			51,
			192,
			72,
			139,
			156,
			36,
			128,
			0,
			0,
			0,
			72,
			131,
			196,
			112,
			93,
			195,
			72,
			139,
			66,
			32,
			185,
			byte.MaxValue,
			byte.MaxValue,
			31,
			0,
			137,
			8,
			72,
			139,
			66,
			32,
			137,
			72,
			4,
			51,
			192,
			195,
			204,
			204,
			204,
			72,
			131,
			236,
			40,
			72,
			141,
			13,
			177,
			2,
			0,
			0,
			232,
			28,
			0,
			0,
			0,
			131,
			61,
			221,
			42,
			0,
			0,
			1,
			117,
			13,
			72,
			139,
			13,
			220,
			42,
			0,
			0,
			byte.MaxValue,
			21,
			222,
			11,
			0,
			0,
			72,
			131,
			196,
			40,
			195,
			204,
			byte.MaxValue,
			37,
			226,
			11,
			0,
			0,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			byte.MaxValue,
			37,
			154,
			11,
			0,
			0,
			byte.MaxValue,
			37,
			140,
			11,
			0,
			0,
			byte.MaxValue,
			37,
			126,
			11,
			0,
			0,
			byte.MaxValue,
			37,
			144,
			11,
			0,
			0,
			194,
			0,
			0,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			102,
			102,
			15,
			31,
			132,
			0,
			0,
			0,
			0,
			0,
			byte.MaxValue,
			224,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			102,
			102,
			15,
			31,
			132,
			0,
			0,
			0,
			0,
			0,
			77,
			51,
			219,
			byte.MaxValue,
			37,
			175,
			11,
			0,
			0,
			204,
			73,
			131,
			203,
			1,
			235,
			243,
			73,
			131,
			203,
			2,
			235,
			237,
			73,
			131,
			203,
			3,
			235,
			231,
			73,
			131,
			203,
			4,
			235,
			225,
			73,
			131,
			203,
			5,
			235,
			219,
			204,
			204,
			204,
			204,
			204,
			204,
			102,
			144,
			73,
			139,
			195,
			72,
			131,
			224,
			7,
			133,
			192,
			117,
			16,
			72,
			139,
			20,
			36,
			100,
			76,
			139,
			4,
			36,
			185,
			44,
			0,
			0,
			0,
			205,
			41,
			60,
			3,
			116,
			31,
			76,
			139,
			193,
			60,
			1,
			116,
			24,
			76,
			139,
			194,
			60,
			2,
			116,
			17,
			77,
			139,
			193,
			60,
			4,
			116,
			10,
			77,
			139,
			194,
			60,
			5,
			116,
			3,
			77,
			51,
			192,
			76,
			51,
			216,
			73,
			139,
			19,
			235,
			206,
			204,
			204,
			204,
			204,
			204,
			204,
			15,
			31,
			64,
			0,
			byte.MaxValue,
			37,
			58,
			11,
			0,
			0,
			204,
			204,
			204,
			204,
			204,
			204,
			15,
			31,
			64,
			0,
			195,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			72,
			139,
			193,
			73,
			131,
			248,
			8,
			114,
			44,
			15,
			182,
			210,
			73,
			185,
			1,
			1,
			1,
			1,
			1,
			1,
			1,
			1,
			73,
			15,
			175,
			209,
			73,
			131,
			248,
			71,
			115,
			96,
			77,
			139,
			200,
			73,
			131,
			225,
			248,
			73,
			3,
			201,
			73,
			137,
			84,
			1,
			248,
			73,
			131,
			233,
			8,
			117,
			245,
			73,
			131,
			224,
			7,
			116,
			15,
			15,
			31,
			68,
			0,
			0,
			65,
			136,
			84,
			8,
			byte.MaxValue,
			73,
			byte.MaxValue,
			200,
			117,
			246,
			144,
			195,
			102,
			102,
			102,
			102,
			102,
			102,
			102,
			15,
			31,
			132,
			0,
			0,
			0,
			0,
			0,
			102,
			102,
			102,
			102,
			102,
			102,
			102,
			15,
			31,
			132,
			0,
			0,
			0,
			0,
			0,
			102,
			102,
			102,
			102,
			102,
			102,
			102,
			15,
			31,
			132,
			0,
			0,
			0,
			0,
			0,
			15,
			31,
			128,
			0,
			0,
			0,
			0,
			247,
			217,
			131,
			225,
			7,
			116,
			6,
			76,
			43,
			193,
			72,
			137,
			16,
			72,
			3,
			200,
			77,
			139,
			200,
			73,
			193,
			233,
			3,
			77,
			139,
			209,
			73,
			193,
			234,
			3,
			73,
			131,
			225,
			7,
			116,
			28,
			73,
			131,
			233,
			8,
			74,
			141,
			12,
			201,
			73,
			247,
			217,
			73,
			byte.MaxValue,
			194,
			76,
			141,
			29,
			6,
			0,
			0,
			0,
			79,
			141,
			28,
			139,
			65,
			byte.MaxValue,
			227,
			72,
			137,
			17,
			72,
			137,
			81,
			8,
			72,
			137,
			81,
			16,
			72,
			137,
			81,
			24,
			72,
			137,
			81,
			32,
			72,
			137,
			81,
			40,
			72,
			137,
			81,
			48,
			72,
			137,
			81,
			56,
			72,
			131,
			193,
			64,
			73,
			byte.MaxValue,
			202,
			117,
			216,
			73,
			131,
			224,
			7,
			116,
			10,
			65,
			136,
			84,
			8,
			byte.MaxValue,
			73,
			byte.MaxValue,
			200,
			117,
			246,
			144,
			195,
			204,
			204,
			204,
			204,
			204,
			204,
			199,
			253,
			182,
			175,
			188,
			211,
			212,
			216,
			179,
			201,
			185,
			166,
			66,
			121,
			58,
			81,
			81,
			49,
			49,
			49,
			52,
			49,
			51,
			53,
			49,
			56,
			56,
			0,
			204,
			204,
			204,
			204,
			50,
			0,
			53,
			0,
			52,
			0,
			52,
			0,
			52,
			0,
			0,
			0,
			204,
			204,
			204,
			204,
			187,
			216,
			181,
			247,
			180,
			180,
			189,
			168,
			186,
			197,
			179,
			201,
			185,
			166,
			10,
			32,
			66,
			121,
			58,
			81,
			81,
			49,
			49,
			49,
			52,
			49,
			51,
			53,
			49,
			56,
			56,
			0,
			65,
			100,
			100,
			114,
			58,
			37,
			88,
			10,
			0,
			204,
			204,
			204,
			204,
			204,
			204,
			204,
			187,
			216,
			181,
			247,
			180,
			180,
			189,
			168,
			202,
			167,
			176,
			220,
			37,
			88,
			0,
			204,
			199,
			253,
			182,
			175,
			208,
			182,
			212,
			216,
			32,
			66,
			121,
			58,
			81,
			81,
			49,
			49,
			49,
			52,
			49,
			51,
			53,
			49,
			56,
			56,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			204,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			186,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			166,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			226,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			90,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			142,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			66,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			44,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			32,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			112,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			8,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			136,
			20,
			0,
			64,
			1,
			0,
			0,
			0,
			160,
			20,
			0,
			64,
			1,
			0,
			0,
			0,
			240,
			20,
			0,
			64,
			1,
			0,
			0,
			0,
			80,
			21,
			0,
			64,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			75,
			0,
			109,
			0,
			100,
			0,
			102,
			0,
			76,
			0,
			105,
			0,
			98,
			0,
			114,
			0,
			97,
			0,
			114,
			0,
			121,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			203,
			15,
			43,
			91,
			0,
			0,
			0,
			0,
			2,
			0,
			0,
			0,
			89,
			0,
			0,
			0,
			228,
			33,
			0,
			0,
			228,
			13,
			0,
			0,
			0,
			0,
			0,
			0,
			203,
			15,
			43,
			91,
			0,
			0,
			0,
			0,
			13,
			0,
			0,
			0,
			228,
			1,
			0,
			0,
			64,
			34,
			0,
			0,
			64,
			14,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			244,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			48,
			48,
			0,
			64,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			104,
			32,
			0,
			64,
			1,
			0,
			0,
			0,
			112,
			32,
			0,
			64,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			82,
			83,
			68,
			83,
			216,
			26,
			65,
			42,
			215,
			152,
			153,
			72,
			159,
			217,
			58,
			98,
			95,
			167,
			99,
			49,
			1,
			0,
			0,
			0,
			67,
			58,
			92,
			85,
			115,
			101,
			114,
			115,
			92,
			65,
			100,
			109,
			105,
			110,
			105,
			115,
			116,
			114,
			97,
			116,
			111,
			114,
			92,
			68,
			101,
			115,
			107,
			116,
			111,
			112,
			92,
			67,
			97,
			108,
			108,
			66,
			97,
			99,
			107,
			92,
			120,
			54,
			52,
			92,
			82,
			101,
			108,
			101,
			97,
			115,
			101,
			92,
			67,
			97,
			108,
			108,
			66,
			97,
			99,
			107,
			46,
			112,
			100,
			98,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			32,
			3,
			0,
			0,
			46,
			116,
			101,
			120,
			116,
			0,
			0,
			0,
			32,
			19,
			0,
			0,
			112,
			1,
			0,
			0,
			46,
			116,
			101,
			120,
			116,
			36,
			109,
			110,
			0,
			0,
			0,
			0,
			144,
			20,
			0,
			0,
			240,
			0,
			0,
			0,
			46,
			116,
			101,
			120,
			116,
			36,
			109,
			110,
			36,
			48,
			48,
			0,
			128,
			21,
			0,
			0,
			0,
			1,
			0,
			0,
			46,
			116,
			101,
			120,
			116,
			36,
			109,
			110,
			36,
			50,
			49,
			0,
			128,
			22,
			0,
			0,
			137,
			0,
			0,
			0,
			46,
			116,
			101,
			120,
			116,
			36,
			115,
			0,
			0,
			32,
			0,
			0,
			104,
			0,
			0,
			0,
			46,
			105,
			100,
			97,
			116,
			97,
			36,
			53,
			0,
			0,
			0,
			0,
			104,
			32,
			0,
			0,
			40,
			0,
			0,
			0,
			46,
			48,
			48,
			99,
			102,
			103,
			0,
			0,
			144,
			32,
			0,
			0,
			84,
			1,
			0,
			0,
			46,
			114,
			100,
			97,
			116,
			97,
			0,
			0,
			228,
			33,
			0,
			0,
			68,
			2,
			0,
			0,
			46,
			114,
			100,
			97,
			116,
			97,
			36,
			122,
			122,
			122,
			100,
			98,
			103,
			0,
			0,
			0,
			40,
			36,
			0,
			0,
			120,
			0,
			0,
			0,
			46,
			120,
			100,
			97,
			116,
			97,
			0,
			0,
			0,
			48,
			0,
			0,
			64,
			0,
			0,
			0,
			46,
			100,
			97,
			116,
			97,
			0,
			0,
			0,
			64,
			48,
			0,
			0,
			16,
			0,
			0,
			0,
			46,
			107,
			109,
			100,
			102,
			99,
			108,
			97,
			115,
			115,
			98,
			105,
			110,
			100,
			36,
			97,
			0,
			0,
			0,
			0,
			80,
			48,
			0,
			0,
			8,
			0,
			0,
			0,
			46,
			107,
			109,
			100,
			102,
			99,
			108,
			97,
			115,
			115,
			98,
			105,
			110,
			100,
			36,
			99,
			0,
			0,
			0,
			0,
			88,
			48,
			0,
			0,
			8,
			0,
			0,
			0,
			46,
			107,
			109,
			100,
			102,
			99,
			108,
			97,
			115,
			115,
			98,
			105,
			110,
			100,
			36,
			100,
			0,
			0,
			0,
			0,
			96,
			48,
			0,
			0,
			16,
			0,
			0,
			0,
			46,
			107,
			109,
			100,
			102,
			116,
			121,
			112,
			101,
			105,
			110,
			105,
			116,
			36,
			97,
			0,
			112,
			48,
			0,
			0,
			16,
			0,
			0,
			0,
			46,
			107,
			109,
			100,
			102,
			116,
			121,
			112,
			101,
			105,
			110,
			105,
			116,
			36,
			99,
			0,
			128,
			48,
			0,
			0,
			184,
			14,
			0,
			0,
			46,
			98,
			115,
			115,
			0,
			0,
			0,
			0,
			0,
			64,
			0,
			0,
			180,
			0,
			0,
			0,
			46,
			112,
			100,
			97,
			116,
			97,
			0,
			0,
			0,
			80,
			0,
			0,
			4,
			0,
			0,
			0,
			46,
			103,
			102,
			105,
			100,
			115,
			36,
			121,
			0,
			0,
			0,
			0,
			0,
			96,
			0,
			0,
			100,
			0,
			0,
			0,
			73,
			78,
			73,
			84,
			0,
			0,
			0,
			0,
			100,
			96,
			0,
			0,
			40,
			0,
			0,
			0,
			46,
			105,
			100,
			97,
			116,
			97,
			36,
			50,
			0,
			0,
			0,
			0,
			140,
			96,
			0,
			0,
			20,
			0,
			0,
			0,
			46,
			105,
			100,
			97,
			116,
			97,
			36,
			51,
			0,
			0,
			0,
			0,
			160,
			96,
			0,
			0,
			104,
			0,
			0,
			0,
			46,
			105,
			100,
			97,
			116,
			97,
			36,
			52,
			0,
			0,
			0,
			0,
			8,
			97,
			0,
			0,
			254,
			0,
			0,
			0,
			46,
			105,
			100,
			97,
			116,
			97,
			36,
			54,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			2,
			4,
			3,
			0,
			1,
			22,
			0,
			6,
			4,
			66,
			0,
			0,
			2,
			13,
			6,
			0,
			2,
			22,
			0,
			6,
			13,
			52,
			16,
			0,
			13,
			210,
			6,
			80,
			0,
			0,
			0,
			0,
			2,
			0,
			2,
			0,
			1,
			22,
			175,
			6,
			1,
			4,
			1,
			0,
			4,
			66,
			0,
			0,
			1,
			20,
			8,
			0,
			20,
			100,
			8,
			0,
			20,
			84,
			7,
			0,
			20,
			52,
			6,
			0,
			20,
			50,
			16,
			112,
			1,
			15,
			6,
			0,
			15,
			100,
			7,
			0,
			15,
			52,
			6,
			0,
			15,
			50,
			11,
			112,
			1,
			10,
			4,
			0,
			10,
			52,
			6,
			0,
			10,
			50,
			6,
			112,
			2,
			0,
			2,
			0,
			2,
			22,
			0,
			6,
			1,
			0,
			0,
			0,
			1,
			0,
			0,
			0,
			1,
			0,
			0,
			0,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			48,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			144,
			32,
			0,
			64,
			1,
			0,
			0,
			0,
			1,
			0,
			0,
			0,
			9,
			0,
			0,
			0,
			176,
			29,
			0,
			0,
			140,
			1,
			0,
			0,
			128,
			48,
			0,
			64,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			50,
			162,
			223,
			45,
			153,
			43,
			0,
			0,
			205,
			93,
			32,
			210,
			102,
			212,
			byte.MaxValue,
			byte.MaxValue,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			64,
			48,
			0,
			64,
			1,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			16,
			0,
			0,
			46,
			16,
			0,
			0,
			80,
			36,
			0,
			0,
			56,
			16,
			0,
			0,
			95,
			16,
			0,
			0,
			80,
			36,
			0,
			0,
			96,
			16,
			0,
			0,
			130,
			17,
			0,
			0,
			88,
			36,
			0,
			0,
			132,
			17,
			0,
			0,
			174,
			17,
			0,
			0,
			124,
			36,
			0,
			0,
			176,
			17,
			0,
			0,
			39,
			18,
			0,
			0,
			124,
			36,
			0,
			0,
			40,
			18,
			0,
			0,
			173,
			18,
			0,
			0,
			108,
			36,
			0,
			0,
			176,
			18,
			0,
			0,
			20,
			19,
			0,
			0,
			124,
			36,
			0,
			0,
			32,
			19,
			0,
			0,
			28,
			20,
			0,
			0,
			52,
			36,
			0,
			0,
			52,
			20,
			0,
			0,
			95,
			20,
			0,
			0,
			40,
			36,
			0,
			0,
			160,
			20,
			0,
			0,
			162,
			20,
			0,
			0,
			136,
			36,
			0,
			0,
			192,
			20,
			0,
			0,
			232,
			20,
			0,
			0,
			144,
			36,
			0,
			0,
			240,
			20,
			0,
			0,
			54,
			21,
			0,
			0,
			148,
			36,
			0,
			0,
			64,
			21,
			0,
			0,
			70,
			21,
			0,
			0,
			152,
			36,
			0,
			0,
			80,
			21,
			0,
			0,
			81,
			21,
			0,
			0,
			156,
			36,
			0,
			0,
			128,
			21,
			0,
			0,
			122,
			22,
			0,
			0,
			72,
			36,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			13,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			72,
			139,
			5,
			41,
			208,
			byte.MaxValue,
			byte.MaxValue,
			69,
			51,
			201,
			73,
			184,
			50,
			162,
			223,
			45,
			153,
			43,
			0,
			0,
			72,
			133,
			192,
			116,
			5,
			73,
			59,
			192,
			117,
			56,
			15,
			49,
			72,
			193,
			226,
			32,
			72,
			141,
			13,
			5,
			208,
			byte.MaxValue,
			byte.MaxValue,
			72,
			11,
			194,
			72,
			51,
			193,
			72,
			137,
			5,
			248,
			207,
			byte.MaxValue,
			byte.MaxValue,
			102,
			68,
			137,
			13,
			246,
			207,
			byte.MaxValue,
			byte.MaxValue,
			72,
			139,
			5,
			233,
			207,
			byte.MaxValue,
			byte.MaxValue,
			72,
			133,
			192,
			117,
			10,
			73,
			139,
			192,
			72,
			137,
			5,
			218,
			207,
			byte.MaxValue,
			byte.MaxValue,
			72,
			247,
			208,
			72,
			137,
			5,
			216,
			207,
			byte.MaxValue,
			byte.MaxValue,
			195,
			204,
			204,
			204,
			200,
			96,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			128,
			97,
			0,
			0,
			40,
			32,
			0,
			0,
			160,
			96,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			250,
			97,
			0,
			0,
			0,
			32,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			204,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			186,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			166,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			226,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			90,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			142,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			66,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			44,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			32,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			112,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			8,
			97,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			194,
			7,
			82,
			116,
			108,
			73,
			110,
			105,
			116,
			85,
			110,
			105,
			99,
			111,
			100,
			101,
			83,
			116,
			114,
			105,
			110,
			103,
			0,
			0,
			87,
			0,
			68,
			98,
			103,
			80,
			114,
			105,
			110,
			116,
			0,
			0,
			208,
			5,
			79,
			98,
			82,
			101,
			103,
			105,
			115,
			116,
			101,
			114,
			67,
			97,
			108,
			108,
			98,
			97,
			99,
			107,
			115,
			0,
			213,
			5,
			79,
			98,
			85,
			110,
			82,
			101,
			103,
			105,
			115,
			116,
			101,
			114,
			67,
			97,
			108,
			108,
			98,
			97,
			99,
			107,
			115,
			0,
			185,
			5,
			79,
			98,
			71,
			101,
			116,
			70,
			105,
			108,
			116,
			101,
			114,
			86,
			101,
			114,
			115,
			105,
			111,
			110,
			0,
			0,
			174,
			6,
			80,
			115,
			80,
			114,
			111,
			99,
			101,
			115,
			115,
			84,
			121,
			112,
			101,
			0,
			110,
			116,
			111,
			115,
			107,
			114,
			110,
			108,
			46,
			101,
			120,
			101,
			0,
			0,
			45,
			7,
			82,
			116,
			108,
			67,
			111,
			112,
			121,
			85,
			110,
			105,
			99,
			111,
			100,
			101,
			83,
			116,
			114,
			105,
			110,
			103,
			0,
			0,
			8,
			0,
			87,
			100,
			102,
			86,
			101,
			114,
			115,
			105,
			111,
			110,
			85,
			110,
			98,
			105,
			110,
			100,
			0,
			0,
			6,
			0,
			87,
			100,
			102,
			86,
			101,
			114,
			115,
			105,
			111,
			110,
			66,
			105,
			110,
			100,
			0,
			0,
			7,
			0,
			87,
			100,
			102,
			86,
			101,
			114,
			115,
			105,
			111,
			110,
			66,
			105,
			110,
			100,
			67,
			108,
			97,
			115,
			115,
			0,
			9,
			0,
			87,
			100,
			102,
			86,
			101,
			114,
			115,
			105,
			111,
			110,
			85,
			110,
			98,
			105,
			110,
			100,
			67,
			108,
			97,
			115,
			115,
			0,
			87,
			68,
			70,
			76,
			68,
			82,
			46,
			83,
			89,
			83,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			32,
			0,
			0,
			24,
			0,
			0,
			0,
			104,
			160,
			112,
			160,
			120,
			160,
			128,
			160,
			72,
			161,
			96,
			161,
			104,
			161,
			0,
			0,
			0,
			48,
			0,
			0,
			16,
			0,
			0,
			0,
			8,
			160,
			32,
			160,
			88,
			160,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			112,
			17,
			0,
			0,
			0,
			2,
			2,
			0,
			48,
			130,
			17,
			100,
			6,
			9,
			42,
			134,
			72,
			134,
			247,
			13,
			1,
			7,
			2,
			160,
			130,
			17,
			85,
			48,
			130,
			17,
			81,
			2,
			1,
			1,
			49,
			11,
			48,
			9,
			6,
			5,
			43,
			14,
			3,
			2,
			26,
			5,
			0,
			48,
			76,
			6,
			10,
			43,
			6,
			1,
			4,
			1,
			130,
			55,
			2,
			1,
			4,
			160,
			62,
			48,
			60,
			48,
			23,
			6,
			10,
			43,
			6,
			1,
			4,
			1,
			130,
			55,
			2,
			1,
			15,
			48,
			9,
			3,
			1,
			0,
			160,
			4,
			162,
			2,
			128,
			0,
			48,
			33,
			48,
			9,
			6,
			5,
			43,
			14,
			3,
			2,
			26,
			5,
			0,
			4,
			20,
			243,
			51,
			139,
			137,
			251,
			162,
			208,
			137,
			155,
			104,
			7,
			106,
			44,
			145,
			90,
			197,
			7,
			46,
			65,
			66,
			160,
			130,
			15,
			7,
			48,
			130,
			4,
			252,
			48,
			130,
			3,
			228,
			160,
			3,
			2,
			1,
			2,
			2,
			16,
			17,
			234,
			155,
			71,
			237,
			197,
			53,
			119,
			52,
			15,
			161,
			78,
			20,
			126,
			145,
			50,
			48,
			13,
			6,
			9,
			42,
			134,
			72,
			134,
			247,
			13,
			1,
			1,
			5,
			5,
			0,
			48,
			129,
			182,
			49,
			11,
			48,
			9,
			6,
			3,
			85,
			4,
			6,
			19,
			2,
			85,
			83,
			49,
			23,
			48,
			21,
			6,
			3,
			85,
			4,
			10,
			19,
			14,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			44,
			32,
			73,
			110,
			99,
			46,
			49,
			31,
			48,
			29,
			6,
			3,
			85,
			4,
			11,
			19,
			22,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			32,
			84,
			114,
			117,
			115,
			116,
			32,
			78,
			101,
			116,
			119,
			111,
			114,
			107,
			49,
			59,
			48,
			57,
			6,
			3,
			85,
			4,
			11,
			19,
			50,
			84,
			101,
			114,
			109,
			115,
			32,
			111,
			102,
			32,
			117,
			115,
			101,
			32,
			97,
			116,
			32,
			104,
			116,
			116,
			112,
			115,
			58,
			47,
			47,
			119,
			119,
			119,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			114,
			112,
			97,
			32,
			40,
			99,
			41,
			48,
			57,
			49,
			48,
			48,
			46,
			6,
			3,
			85,
			4,
			3,
			19,
			39,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			32,
			67,
			108,
			97,
			115,
			115,
			32,
			51,
			32,
			67,
			111,
			100,
			101,
			32,
			83,
			105,
			103,
			110,
			105,
			110,
			103,
			32,
			50,
			48,
			48,
			57,
			45,
			50,
			32,
			67,
			65,
			48,
			30,
			23,
			13,
			49,
			48,
			48,
			50,
			50,
			50,
			48,
			48,
			48,
			48,
			48,
			48,
			90,
			23,
			13,
			49,
			50,
			48,
			50,
			50,
			50,
			50,
			51,
			53,
			57,
			53,
			57,
			90,
			48,
			129,
			185,
			49,
			11,
			48,
			9,
			6,
			3,
			85,
			4,
			6,
			19,
			2,
			84,
			87,
			49,
			15,
			48,
			13,
			6,
			3,
			85,
			4,
			8,
			19,
			6,
			84,
			97,
			105,
			119,
			97,
			110,
			49,
			17,
			48,
			15,
			6,
			3,
			85,
			4,
			7,
			19,
			8,
			84,
			97,
			105,
			99,
			104,
			117,
			110,
			103,
			49,
			34,
			48,
			32,
			6,
			3,
			85,
			4,
			10,
			20,
			25,
			88,
			116,
			114,
			101,
			97,
			109,
			105,
			110,
			103,
			32,
			84,
			101,
			99,
			104,
			110,
			111,
			108,
			111,
			103,
			121,
			32,
			73,
			110,
			99,
			46,
			49,
			62,
			48,
			60,
			6,
			3,
			85,
			4,
			11,
			19,
			53,
			68,
			105,
			103,
			105,
			116,
			97,
			108,
			32,
			73,
			68,
			32,
			67,
			108,
			97,
			115,
			115,
			32,
			51,
			32,
			45,
			32,
			77,
			105,
			99,
			114,
			111,
			115,
			111,
			102,
			116,
			32,
			83,
			111,
			102,
			116,
			119,
			97,
			114,
			101,
			32,
			86,
			97,
			108,
			105,
			100,
			97,
			116,
			105,
			111,
			110,
			32,
			118,
			50,
			49,
			34,
			48,
			32,
			6,
			3,
			85,
			4,
			3,
			20,
			25,
			88,
			116,
			114,
			101,
			97,
			109,
			105,
			110,
			103,
			32,
			84,
			101,
			99,
			104,
			110,
			111,
			108,
			111,
			103,
			121,
			32,
			73,
			110,
			99,
			46,
			48,
			129,
			159,
			48,
			13,
			6,
			9,
			42,
			134,
			72,
			134,
			247,
			13,
			1,
			1,
			1,
			5,
			0,
			3,
			129,
			141,
			0,
			48,
			129,
			137,
			2,
			129,
			129,
			0,
			174,
			68,
			185,
			247,
			251,
			222,
			176,
			41,
			123,
			189,
			224,
			39,
			251,
			15,
			4,
			180,
			181,
			125,
			184,
			178,
			212,
			187,
			77,
			245,
			187,
			226,
			99,
			108,
			233,
			115,
			186,
			14,
			69,
			214,
			8,
			60,
			101,
			50,
			148,
			58,
			30,
			60,
			35,
			238,
			25,
			162,
			155,
			135,
			205,
			159,
			48,
			115,
			82,
			12,
			202,
			1,
			10,
			145,
			130,
			242,
			45,
			176,
			64,
			24,
			217,
			209,
			58,
			241,
			8,
			86,
			123,
			50,
			153,
			byte.MaxValue,
			195,
			51,
			179,
			174,
			235,
			72,
			253,
			187,
			107,
			203,
			210,
			34,
			153,
			19,
			129,
			33,
			152,
			0,
			75,
			155,
			43,
			124,
			118,
			75,
			69,
			223,
			101,
			214,
			63,
			38,
			84,
			29,
			200,
			199,
			155,
			140,
			115,
			111,
			220,
			102,
			136,
			207,
			240,
			149,
			244,
			225,
			68,
			214,
			253,
			18,
			251,
			88,
			174,
			151,
			2,
			3,
			1,
			0,
			1,
			163,
			130,
			1,
			131,
			48,
			130,
			1,
			127,
			48,
			9,
			6,
			3,
			85,
			29,
			19,
			4,
			2,
			48,
			0,
			48,
			14,
			6,
			3,
			85,
			29,
			15,
			1,
			1,
			byte.MaxValue,
			4,
			4,
			3,
			2,
			7,
			128,
			48,
			68,
			6,
			3,
			85,
			29,
			31,
			4,
			61,
			48,
			59,
			48,
			57,
			160,
			55,
			160,
			53,
			134,
			51,
			104,
			116,
			116,
			112,
			58,
			47,
			47,
			99,
			115,
			99,
			51,
			45,
			50,
			48,
			48,
			57,
			45,
			50,
			45,
			99,
			114,
			108,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			67,
			83,
			67,
			51,
			45,
			50,
			48,
			48,
			57,
			45,
			50,
			46,
			99,
			114,
			108,
			48,
			68,
			6,
			3,
			85,
			29,
			32,
			4,
			61,
			48,
			59,
			48,
			57,
			6,
			11,
			96,
			134,
			72,
			1,
			134,
			248,
			69,
			1,
			7,
			23,
			3,
			48,
			42,
			48,
			40,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			2,
			1,
			22,
			28,
			104,
			116,
			116,
			112,
			115,
			58,
			47,
			47,
			119,
			119,
			119,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			114,
			112,
			97,
			48,
			19,
			6,
			3,
			85,
			29,
			37,
			4,
			12,
			48,
			10,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			3,
			3,
			48,
			117,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			1,
			1,
			4,
			105,
			48,
			103,
			48,
			36,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			48,
			1,
			134,
			24,
			104,
			116,
			116,
			112,
			58,
			47,
			47,
			111,
			99,
			115,
			112,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			48,
			63,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			48,
			2,
			134,
			51,
			104,
			116,
			116,
			112,
			58,
			47,
			47,
			99,
			115,
			99,
			51,
			45,
			50,
			48,
			48,
			57,
			45,
			50,
			45,
			97,
			105,
			97,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			67,
			83,
			67,
			51,
			45,
			50,
			48,
			48,
			57,
			45,
			50,
			46,
			99,
			101,
			114,
			48,
			31,
			6,
			3,
			85,
			29,
			35,
			4,
			24,
			48,
			22,
			128,
			20,
			151,
			208,
			107,
			168,
			38,
			112,
			200,
			161,
			63,
			148,
			31,
			8,
			45,
			196,
			53,
			155,
			164,
			161,
			30,
			242,
			48,
			17,
			6,
			9,
			96,
			134,
			72,
			1,
			134,
			248,
			66,
			1,
			1,
			4,
			4,
			3,
			2,
			4,
			16,
			48,
			22,
			6,
			10,
			43,
			6,
			1,
			4,
			1,
			130,
			55,
			2,
			1,
			27,
			4,
			8,
			48,
			6,
			1,
			1,
			0,
			1,
			1,
			byte.MaxValue,
			48,
			13,
			6,
			9,
			42,
			134,
			72,
			134,
			247,
			13,
			1,
			1,
			5,
			5,
			0,
			3,
			130,
			1,
			1,
			0,
			89,
			22,
			221,
			93,
			241,
			28,
			163,
			byte.MaxValue,
			17,
			45,
			133,
			17,
			101,
			186,
			185,
			200,
			140,
			230,
			223,
			117,
			77,
			109,
			209,
			77,
			226,
			189,
			90,
			98,
			240,
			164,
			31,
			248,
			37,
			17,
			225,
			40,
			190,
			245,
			59,
			232,
			84,
			69,
			196,
			216,
			134,
			233,
			121,
			240,
			26,
			165,
			156,
			161,
			37,
			107,
			32,
			54,
			54,
			20,
			191,
			120,
			231,
			71,
			203,
			178,
			110,
			103,
			102,
			63,
			114,
			149,
			130,
			249,
			31,
			19,
			177,
			171,
			136,
			217,
			241,
			220,
			115,
			86,
			208,
			79,
			140,
			13,
			145,
			100,
			108,
			161,
			252,
			140,
			99,
			194,
			204,
			108,
			134,
			208,
			194,
			100,
			18,
			21,
			142,
			129,
			22,
			52,
			160,
			62,
			138,
			19,
			37,
			230,
			170,
			4,
			9,
			182,
			0,
			26,
			176,
			141,
			116,
			91,
			126,
			10,
			171,
			185,
			154,
			91,
			81,
			249,
			67,
			197,
			102,
			112,
			181,
			221,
			212,
			29,
			154,
			77,
			49,
			140,
			202,
			164,
			46,
			208,
			193,
			198,
			4,
			233,
			19,
			35,
			54,
			191,
			20,
			141,
			169,
			55,
			5,
			192,
			98,
			74,
			80,
			75,
			58,
			245,
			221,
			2,
			181,
			89,
			9,
			124,
			223,
			30,
			206,
			144,
			230,
			36,
			251,
			69,
			252,
			243,
			22,
			89,
			230,
			101,
			99,
			95,
			4,
			96,
			123,
			125,
			185,
			230,
			95,
			2,
			17,
			183,
			66,
			7,
			165,
			87,
			35,
			116,
			188,
			179,
			125,
			218,
			227,
			114,
			211,
			52,
			21,
			216,
			28,
			64,
			203,
			28,
			132,
			50,
			188,
			113,
			175,
			39,
			190,
			18,
			176,
			192,
			153,
			170,
			118,
			138,
			3,
			244,
			151,
			96,
			60,
			177,
			219,
			193,
			40,
			146,
			106,
			82,
			131,
			67,
			210,
			145,
			150,
			47,
			162,
			116,
			64,
			180,
			69,
			129,
			48,
			130,
			4,
			252,
			48,
			130,
			4,
			101,
			160,
			3,
			2,
			1,
			2,
			2,
			16,
			101,
			82,
			38,
			225,
			178,
			46,
			24,
			225,
			89,
			15,
			41,
			133,
			172,
			34,
			231,
			92,
			48,
			13,
			6,
			9,
			42,
			134,
			72,
			134,
			247,
			13,
			1,
			1,
			5,
			5,
			0,
			48,
			95,
			49,
			11,
			48,
			9,
			6,
			3,
			85,
			4,
			6,
			19,
			2,
			85,
			83,
			49,
			23,
			48,
			21,
			6,
			3,
			85,
			4,
			10,
			19,
			14,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			44,
			32,
			73,
			110,
			99,
			46,
			49,
			55,
			48,
			53,
			6,
			3,
			85,
			4,
			11,
			19,
			46,
			67,
			108,
			97,
			115,
			115,
			32,
			51,
			32,
			80,
			117,
			98,
			108,
			105,
			99,
			32,
			80,
			114,
			105,
			109,
			97,
			114,
			121,
			32,
			67,
			101,
			114,
			116,
			105,
			102,
			105,
			99,
			97,
			116,
			105,
			111,
			110,
			32,
			65,
			117,
			116,
			104,
			111,
			114,
			105,
			116,
			121,
			48,
			30,
			23,
			13,
			48,
			57,
			48,
			53,
			50,
			49,
			48,
			48,
			48,
			48,
			48,
			48,
			90,
			23,
			13,
			49,
			57,
			48,
			53,
			50,
			48,
			50,
			51,
			53,
			57,
			53,
			57,
			90,
			48,
			129,
			182,
			49,
			11,
			48,
			9,
			6,
			3,
			85,
			4,
			6,
			19,
			2,
			85,
			83,
			49,
			23,
			48,
			21,
			6,
			3,
			85,
			4,
			10,
			19,
			14,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			44,
			32,
			73,
			110,
			99,
			46,
			49,
			31,
			48,
			29,
			6,
			3,
			85,
			4,
			11,
			19,
			22,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			32,
			84,
			114,
			117,
			115,
			116,
			32,
			78,
			101,
			116,
			119,
			111,
			114,
			107,
			49,
			59,
			48,
			57,
			6,
			3,
			85,
			4,
			11,
			19,
			50,
			84,
			101,
			114,
			109,
			115,
			32,
			111,
			102,
			32,
			117,
			115,
			101,
			32,
			97,
			116,
			32,
			104,
			116,
			116,
			112,
			115,
			58,
			47,
			47,
			119,
			119,
			119,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			114,
			112,
			97,
			32,
			40,
			99,
			41,
			48,
			57,
			49,
			48,
			48,
			46,
			6,
			3,
			85,
			4,
			3,
			19,
			39,
			86,
			101,
			114,
			105,
			83,
			105,
			103,
			110,
			32,
			67,
			108,
			97,
			115,
			115,
			32,
			51,
			32,
			67,
			111,
			100,
			101,
			32,
			83,
			105,
			103,
			110,
			105,
			110,
			103,
			32,
			50,
			48,
			48,
			57,
			45,
			50,
			32,
			67,
			65,
			48,
			130,
			1,
			34,
			48,
			13,
			6,
			9,
			42,
			134,
			72,
			134,
			247,
			13,
			1,
			1,
			1,
			5,
			0,
			3,
			130,
			1,
			15,
			0,
			48,
			130,
			1,
			10,
			2,
			130,
			1,
			1,
			0,
			190,
			103,
			29,
			180,
			96,
			170,
			16,
			73,
			111,
			86,
			23,
			124,
			102,
			201,
			94,
			134,
			13,
			213,
			241,
			172,
			167,
			113,
			131,
			142,
			139,
			137,
			248,
			136,
			4,
			137,
			21,
			6,
			186,
			45,
			132,
			33,
			149,
			228,
			209,
			156,
			80,
			76,
			251,
			210,
			34,
			189,
			218,
			242,
			178,
			53,
			59,
			30,
			143,
			195,
			9,
			251,
			252,
			19,
			46,
			90,
			191,
			137,
			124,
			61,
			59,
			37,
			30,
			246,
			243,
			88,
			123,
			156,
			244,
			1,
			181,
			198,
			10,
			184,
			128,
			206,
			190,
			39,
			116,
			97,
			103,
			39,
			77,
			106,
			229,
			236,
			129,
			97,
			88,
			121,
			163,
			224,
			23,
			16,
			18,
			21,
			39,
			176,
			225,
			77,
			52,
			127,
			43,
			71,
			32,
			68,
			185,
			222,
			102,
			36,
			102,
			138,
			205,
			79,
			186,
			31,
			197,
			56,
			200,
			84,
			144,
			225,
			114,
			246,
			25,
			102,
			117,
			106,
			185,
			73,
			104,
			207,
			56,
			121,
			13,
			170,
			48,
			168,
			219,
			44,
			96,
			72,
			158,
			215,
			170,
			20,
			1,
			169,
			131,
			215,
			56,
			145,
			48,
			57,
			19,
			150,
			3,
			58,
			124,
			64,
			84,
			182,
			173,
			224,
			47,
			27,
			131,
			220,
			168,
			17,
			82,
			62,
			2,
			179,
			215,
			43,
			253,
			33,
			182,
			167,
			92,
			163,
			15,
			11,
			169,
			166,
			16,
			80,
			14,
			52,
			46,
			77,
			167,
			206,
			201,
			94,
			37,
			212,
			140,
			188,
			243,
			110,
			124,
			41,
			188,
			1,
			93,
			252,
			49,
			135,
			90,
			213,
			140,
			133,
			103,
			88,
			136,
			25,
			160,
			191,
			53,
			240,
			234,
			43,
			163,
			33,
			231,
			144,
			246,
			131,
			229,
			168,
			237,
			96,
			120,
			94,
			123,
			96,
			131,
			253,
			87,
			11,
			93,
			65,
			13,
			99,
			84,
			96,
			214,
			67,
			33,
			239,
			2,
			3,
			1,
			0,
			1,
			163,
			130,
			1,
			219,
			48,
			130,
			1,
			215,
			48,
			18,
			6,
			3,
			85,
			29,
			19,
			1,
			1,
			byte.MaxValue,
			4,
			8,
			48,
			6,
			1,
			1,
			byte.MaxValue,
			2,
			1,
			0,
			48,
			112,
			6,
			3,
			85,
			29,
			32,
			4,
			105,
			48,
			103,
			48,
			101,
			6,
			11,
			96,
			134,
			72,
			1,
			134,
			248,
			69,
			1,
			7,
			23,
			3,
			48,
			86,
			48,
			40,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			2,
			1,
			22,
			28,
			104,
			116,
			116,
			112,
			115,
			58,
			47,
			47,
			119,
			119,
			119,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			99,
			112,
			115,
			48,
			42,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			2,
			2,
			48,
			30,
			26,
			28,
			104,
			116,
			116,
			112,
			115,
			58,
			47,
			47,
			119,
			119,
			119,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			111,
			109,
			47,
			114,
			112,
			97,
			48,
			14,
			6,
			3,
			85,
			29,
			15,
			1,
			1,
			byte.MaxValue,
			4,
			4,
			3,
			2,
			1,
			6,
			48,
			109,
			6,
			8,
			43,
			6,
			1,
			5,
			5,
			7,
			1,
			12,
			4,
			97,
			48,
			95,
			161,
			93,
			160,
			91,
			48,
			89,
			48,
			87,
			48,
			85,
			22,
			9,
			105,
			109,
			97,
			103,
			101,
			47,
			103,
			105,
			102,
			48,
			33,
			48,
			31,
			48,
			7,
			6,
			5,
			43,
			14,
			3,
			2,
			26,
			4,
			20,
			143,
			229,
			211,
			26,
			134,
			172,
			141,
			142,
			107,
			195,
			207,
			128,
			106,
			212,
			72,
			24,
			44,
			123,
			25,
			46,
			48,
			37,
			22,
			35,
			104,
			116,
			116,
			112,
			58,
			47,
			47,
			108,
			111,
			103,
			111,
			46,
			118,
			101,
			114,
			105,
			115,
			105,
			103,
			110,
			46,
			99,
			"Not showing all elements because this array is too big (12144 elements)"
		};

		// Token: 0x04000025 RID: 37
		private const int PROCESS_CREATE_THREAD = 2;

		// Token: 0x04000026 RID: 38
		private const int PROCESS_QUERY_INFORMATION = 1024;

		// Token: 0x04000027 RID: 39
		private const int PROCESS_VM_OPERATION = 8;

		// Token: 0x04000028 RID: 40
		private const int PROCESS_VM_WRITE = 32;

		// Token: 0x04000029 RID: 41
		private const int PROCESS_VM_READ = 16;

		// Token: 0x0400002A RID: 42
		private const uint MEM_FREE = 65536U;

		// Token: 0x0400002B RID: 43
		private const uint MEM_COMMIT = 4096U;

		// Token: 0x0400002C RID: 44
		private const uint MEM_RESERVE = 8192U;

		// Token: 0x0400002D RID: 45
		private const uint PAGE_READONLY = 2U;

		// Token: 0x0400002E RID: 46
		private const uint PAGE_READWRITE = 4U;

		// Token: 0x0400002F RID: 47
		private const uint PAGE_WRITECOPY = 8U;

		// Token: 0x04000030 RID: 48
		private const uint PAGE_EXECUTE_READWRITE = 64U;

		// Token: 0x04000031 RID: 49
		private const uint PAGE_EXECUTE_WRITECOPY = 128U;

		// Token: 0x04000032 RID: 50
		private const uint PAGE_EXECUTE = 16U;

		// Token: 0x04000033 RID: 51
		private const uint PAGE_EXECUTE_READ = 32U;

		// Token: 0x04000034 RID: 52
		private const uint PAGE_GUARD = 256U;

		// Token: 0x04000035 RID: 53
		private const uint PAGE_NOACCESS = 1U;

		// Token: 0x04000036 RID: 54
		private uint MEM_PRIVATE = 131072U;

		// Token: 0x04000037 RID: 55
		private uint MEM_IMAGE = 16777216U;

		// Token: 0x04000038 RID: 56
		public IntPtr pHandle;

		// Token: 0x04000039 RID: 57
		private Dictionary<string, CancellationTokenSource> FreezeTokenSrcs = new Dictionary<string, CancellationTokenSource>();

		// Token: 0x0400003A RID: 58
		public Process theProc = null;

		// Token: 0x0400003B RID: 59
		private bool _is64Bit;

		// Token: 0x0400003C RID: 60
		public Dictionary<string, IntPtr> modules = new Dictionary<string, IntPtr>();

		// Token: 0x0400003D RID: 61
		private ProcessModule mainModule;

		// Token: 0x02000007 RID: 7
		internal struct MemoryRegionResult
		{
			// Token: 0x17000005 RID: 5
			// (get) Token: 0x060000BC RID: 188 RVA: 0x00006F37 File Offset: 0x00005137
			// (set) Token: 0x060000BD RID: 189 RVA: 0x00006F3F File Offset: 0x0000513F
			public UIntPtr CurrentBaseAddress { get; set; }

			// Token: 0x17000006 RID: 6
			// (get) Token: 0x060000BE RID: 190 RVA: 0x00006F48 File Offset: 0x00005148
			// (set) Token: 0x060000BF RID: 191 RVA: 0x00006F50 File Offset: 0x00005150
			public long RegionSize { get; set; }

			// Token: 0x17000007 RID: 7
			// (get) Token: 0x060000C0 RID: 192 RVA: 0x00006F59 File Offset: 0x00005159
			// (set) Token: 0x060000C1 RID: 193 RVA: 0x00006F61 File Offset: 0x00005161
			public UIntPtr RegionBase { get; set; }
		}

		// Token: 0x02000008 RID: 8
		public enum NtStatus : uint
		{
			// Token: 0x0400004C RID: 76
			Success,
			// Token: 0x0400004D RID: 77
			Wait0 = 0U,
			// Token: 0x0400004E RID: 78
			Wait1,
			// Token: 0x0400004F RID: 79
			Wait2,
			// Token: 0x04000050 RID: 80
			Wait3,
			// Token: 0x04000051 RID: 81
			Wait63 = 63U,
			// Token: 0x04000052 RID: 82
			Abandoned = 128U,
			// Token: 0x04000053 RID: 83
			AbandonedWait0 = 128U,
			// Token: 0x04000054 RID: 84
			AbandonedWait1,
			// Token: 0x04000055 RID: 85
			AbandonedWait2,
			// Token: 0x04000056 RID: 86
			AbandonedWait3,
			// Token: 0x04000057 RID: 87
			AbandonedWait63 = 191U,
			// Token: 0x04000058 RID: 88
			UserApc,
			// Token: 0x04000059 RID: 89
			KernelApc = 256U,
			// Token: 0x0400005A RID: 90
			Alerted,
			// Token: 0x0400005B RID: 91
			Timeout,
			// Token: 0x0400005C RID: 92
			Pending,
			// Token: 0x0400005D RID: 93
			Reparse,
			// Token: 0x0400005E RID: 94
			MoreEntries,
			// Token: 0x0400005F RID: 95
			NotAllAssigned,
			// Token: 0x04000060 RID: 96
			SomeNotMapped,
			// Token: 0x04000061 RID: 97
			OpLockBreakInProgress,
			// Token: 0x04000062 RID: 98
			VolumeMounted,
			// Token: 0x04000063 RID: 99
			RxActCommitted,
			// Token: 0x04000064 RID: 100
			NotifyCleanup,
			// Token: 0x04000065 RID: 101
			NotifyEnumDir,
			// Token: 0x04000066 RID: 102
			NoQuotasForAccount,
			// Token: 0x04000067 RID: 103
			PrimaryTransportConnectFailed,
			// Token: 0x04000068 RID: 104
			PageFaultTransition = 272U,
			// Token: 0x04000069 RID: 105
			PageFaultDemandZero,
			// Token: 0x0400006A RID: 106
			PageFaultCopyOnWrite,
			// Token: 0x0400006B RID: 107
			PageFaultGuardPage,
			// Token: 0x0400006C RID: 108
			PageFaultPagingFile,
			// Token: 0x0400006D RID: 109
			CrashDump = 278U,
			// Token: 0x0400006E RID: 110
			ReparseObject = 280U,
			// Token: 0x0400006F RID: 111
			NothingToTerminate = 290U,
			// Token: 0x04000070 RID: 112
			ProcessNotInJob,
			// Token: 0x04000071 RID: 113
			ProcessInJob,
			// Token: 0x04000072 RID: 114
			ProcessCloned = 297U,
			// Token: 0x04000073 RID: 115
			FileLockedWithOnlyReaders,
			// Token: 0x04000074 RID: 116
			FileLockedWithWriters,
			// Token: 0x04000075 RID: 117
			Informational = 1073741824U,
			// Token: 0x04000076 RID: 118
			ObjectNameExists = 1073741824U,
			// Token: 0x04000077 RID: 119
			ThreadWasSuspended,
			// Token: 0x04000078 RID: 120
			workingSetLimitRange,
			// Token: 0x04000079 RID: 121
			ImageNotAtBase,
			// Token: 0x0400007A RID: 122
			RegistryRecovered = 1073741833U,
			// Token: 0x0400007B RID: 123
			Warning = 2147483648U,
			// Token: 0x0400007C RID: 124
			GuardPageViolation,
			// Token: 0x0400007D RID: 125
			DatatypeMisalignment,
			// Token: 0x0400007E RID: 126
			Breakpoint,
			// Token: 0x0400007F RID: 127
			SingleStep,
			// Token: 0x04000080 RID: 128
			BufferOverflow,
			// Token: 0x04000081 RID: 129
			NoMoreFiles,
			// Token: 0x04000082 RID: 130
			HandlesClosed = 2147483658U,
			// Token: 0x04000083 RID: 131
			PartialCopy = 2147483661U,
			// Token: 0x04000084 RID: 132
			DeviceBusy = 2147483665U,
			// Token: 0x04000085 RID: 133
			InvalidEaName = 2147483667U,
			// Token: 0x04000086 RID: 134
			EaListInconsistent,
			// Token: 0x04000087 RID: 135
			NoMoreEntries = 2147483674U,
			// Token: 0x04000088 RID: 136
			LongJump = 2147483686U,
			// Token: 0x04000089 RID: 137
			DllMightBeInsecure = 2147483691U,
			// Token: 0x0400008A RID: 138
			Error = 3221225472U,
			// Token: 0x0400008B RID: 139
			Unsuccessful,
			// Token: 0x0400008C RID: 140
			NotImplemented,
			// Token: 0x0400008D RID: 141
			InvalidInfoClass,
			// Token: 0x0400008E RID: 142
			InfoLengthMismatch,
			// Token: 0x0400008F RID: 143
			AccessViolation,
			// Token: 0x04000090 RID: 144
			InPageError,
			// Token: 0x04000091 RID: 145
			PagefileQuota,
			// Token: 0x04000092 RID: 146
			InvalidHandle,
			// Token: 0x04000093 RID: 147
			BadInitialStack,
			// Token: 0x04000094 RID: 148
			BadInitialPc,
			// Token: 0x04000095 RID: 149
			InvalidCid,
			// Token: 0x04000096 RID: 150
			TimerNotCanceled,
			// Token: 0x04000097 RID: 151
			InvalidParameter,
			// Token: 0x04000098 RID: 152
			NoSuchDevice,
			// Token: 0x04000099 RID: 153
			NoSuchFile,
			// Token: 0x0400009A RID: 154
			InvalidDeviceRequest,
			// Token: 0x0400009B RID: 155
			EndOfFile,
			// Token: 0x0400009C RID: 156
			WrongVolume,
			// Token: 0x0400009D RID: 157
			NoMediaInDevice,
			// Token: 0x0400009E RID: 158
			NoMemory = 3221225495U,
			// Token: 0x0400009F RID: 159
			NotMappedView = 3221225497U,
			// Token: 0x040000A0 RID: 160
			UnableToFreeVm,
			// Token: 0x040000A1 RID: 161
			UnableToDeleteSection,
			// Token: 0x040000A2 RID: 162
			IllegalInstruction = 3221225501U,
			// Token: 0x040000A3 RID: 163
			AlreadyCommitted = 3221225505U,
			// Token: 0x040000A4 RID: 164
			AccessDenied,
			// Token: 0x040000A5 RID: 165
			BufferTooSmall,
			// Token: 0x040000A6 RID: 166
			ObjectTypeMismatch,
			// Token: 0x040000A7 RID: 167
			NonContinuableException,
			// Token: 0x040000A8 RID: 168
			BadStack = 3221225512U,
			// Token: 0x040000A9 RID: 169
			NotLocked = 3221225514U,
			// Token: 0x040000AA RID: 170
			NotCommitted = 3221225517U,
			// Token: 0x040000AB RID: 171
			InvalidParameterMix = 3221225520U,
			// Token: 0x040000AC RID: 172
			ObjectNameInvalid = 3221225523U,
			// Token: 0x040000AD RID: 173
			ObjectNameNotFound,
			// Token: 0x040000AE RID: 174
			ObjectNameCollision,
			// Token: 0x040000AF RID: 175
			ObjectPathInvalid = 3221225529U,
			// Token: 0x040000B0 RID: 176
			ObjectPathNotFound,
			// Token: 0x040000B1 RID: 177
			ObjectPathSyntaxBad,
			// Token: 0x040000B2 RID: 178
			DataOverrun,
			// Token: 0x040000B3 RID: 179
			DataLate,
			// Token: 0x040000B4 RID: 180
			DataError,
			// Token: 0x040000B5 RID: 181
			CrcError,
			// Token: 0x040000B6 RID: 182
			SectionTooBig,
			// Token: 0x040000B7 RID: 183
			PortConnectionRefused,
			// Token: 0x040000B8 RID: 184
			InvalidPortHandle,
			// Token: 0x040000B9 RID: 185
			SharingViolation,
			// Token: 0x040000BA RID: 186
			QuotaExceeded,
			// Token: 0x040000BB RID: 187
			InvalidPageProtection,
			// Token: 0x040000BC RID: 188
			MutantNotOwned,
			// Token: 0x040000BD RID: 189
			SemaphoreLimitExceeded,
			// Token: 0x040000BE RID: 190
			PortAlreadySet,
			// Token: 0x040000BF RID: 191
			SectionNotImage,
			// Token: 0x040000C0 RID: 192
			SuspendCountExceeded,
			// Token: 0x040000C1 RID: 193
			ThreadIsTerminating,
			// Token: 0x040000C2 RID: 194
			BadworkingSetLimit,
			// Token: 0x040000C3 RID: 195
			IncompatibleFileMap,
			// Token: 0x040000C4 RID: 196
			SectionProtection,
			// Token: 0x040000C5 RID: 197
			EasNotSupported,
			// Token: 0x040000C6 RID: 198
			EaTooLarge,
			// Token: 0x040000C7 RID: 199
			NonExistentEaEntry,
			// Token: 0x040000C8 RID: 200
			NoEasOnFile,
			// Token: 0x040000C9 RID: 201
			EaCorruptError,
			// Token: 0x040000CA RID: 202
			FileLockConflict,
			// Token: 0x040000CB RID: 203
			LockNotGranted,
			// Token: 0x040000CC RID: 204
			DeletePending,
			// Token: 0x040000CD RID: 205
			CtlFileNotSupported,
			// Token: 0x040000CE RID: 206
			UnknownRevision,
			// Token: 0x040000CF RID: 207
			RevisionMismatch,
			// Token: 0x040000D0 RID: 208
			InvalidOwner,
			// Token: 0x040000D1 RID: 209
			InvalidPrimaryGroup,
			// Token: 0x040000D2 RID: 210
			NoImpersonationToken,
			// Token: 0x040000D3 RID: 211
			CantDisableMandatory,
			// Token: 0x040000D4 RID: 212
			NoLogonServers,
			// Token: 0x040000D5 RID: 213
			NoSuchLogonSession,
			// Token: 0x040000D6 RID: 214
			NoSuchPrivilege,
			// Token: 0x040000D7 RID: 215
			PrivilegeNotHeld,
			// Token: 0x040000D8 RID: 216
			InvalidAccountName,
			// Token: 0x040000D9 RID: 217
			UserExists,
			// Token: 0x040000DA RID: 218
			NoSuchUser,
			// Token: 0x040000DB RID: 219
			GroupExists,
			// Token: 0x040000DC RID: 220
			NoSuchGroup,
			// Token: 0x040000DD RID: 221
			MemberInGroup,
			// Token: 0x040000DE RID: 222
			MemberNotInGroup,
			// Token: 0x040000DF RID: 223
			LastAdmin,
			// Token: 0x040000E0 RID: 224
			WrongPassword,
			// Token: 0x040000E1 RID: 225
			IllFormedPassword,
			// Token: 0x040000E2 RID: 226
			PasswordRestriction,
			// Token: 0x040000E3 RID: 227
			LogonFailure,
			// Token: 0x040000E4 RID: 228
			AccountRestriction,
			// Token: 0x040000E5 RID: 229
			InvalidLogonHours,
			// Token: 0x040000E6 RID: 230
			InvalidWorkstation,
			// Token: 0x040000E7 RID: 231
			PasswordExpired,
			// Token: 0x040000E8 RID: 232
			AccountDisabled,
			// Token: 0x040000E9 RID: 233
			NoneMapped,
			// Token: 0x040000EA RID: 234
			TooManyLuidsRequested,
			// Token: 0x040000EB RID: 235
			LuidsExhausted,
			// Token: 0x040000EC RID: 236
			InvalidSubAuthority,
			// Token: 0x040000ED RID: 237
			InvalidAcl,
			// Token: 0x040000EE RID: 238
			InvalidSid,
			// Token: 0x040000EF RID: 239
			InvalidSecurityDescr,
			// Token: 0x040000F0 RID: 240
			ProcedureNotFound,
			// Token: 0x040000F1 RID: 241
			InvalidImageFormat,
			// Token: 0x040000F2 RID: 242
			NoToken,
			// Token: 0x040000F3 RID: 243
			BadInheritanceAcl,
			// Token: 0x040000F4 RID: 244
			RangeNotLocked,
			// Token: 0x040000F5 RID: 245
			DiskFull,
			// Token: 0x040000F6 RID: 246
			ServerDisabled,
			// Token: 0x040000F7 RID: 247
			ServerNotDisabled,
			// Token: 0x040000F8 RID: 248
			TooManyGuidsRequested,
			// Token: 0x040000F9 RID: 249
			GuidsExhausted,
			// Token: 0x040000FA RID: 250
			InvalidIdAuthority,
			// Token: 0x040000FB RID: 251
			AgentsExhausted,
			// Token: 0x040000FC RID: 252
			InvalidVolumeLabel,
			// Token: 0x040000FD RID: 253
			SectionNotExtended,
			// Token: 0x040000FE RID: 254
			NotMappedData,
			// Token: 0x040000FF RID: 255
			ResourceDataNotFound,
			// Token: 0x04000100 RID: 256
			ResourceTypeNotFound,
			// Token: 0x04000101 RID: 257
			ResourceNameNotFound,
			// Token: 0x04000102 RID: 258
			ArrayBoundsExceeded,
			// Token: 0x04000103 RID: 259
			FloatDenormalOperand,
			// Token: 0x04000104 RID: 260
			FloatDivideByZero,
			// Token: 0x04000105 RID: 261
			FloatInexactResult,
			// Token: 0x04000106 RID: 262
			FloatInvalidOperation,
			// Token: 0x04000107 RID: 263
			FloatOverflow,
			// Token: 0x04000108 RID: 264
			FloatStackCheck,
			// Token: 0x04000109 RID: 265
			FloatUnderflow,
			// Token: 0x0400010A RID: 266
			IntegerDivideByZero,
			// Token: 0x0400010B RID: 267
			IntegerOverflow,
			// Token: 0x0400010C RID: 268
			PrivilegedInstruction,
			// Token: 0x0400010D RID: 269
			TooManyPagingFiles,
			// Token: 0x0400010E RID: 270
			FileInvalid,
			// Token: 0x0400010F RID: 271
			InstanceNotAvailable = 3221225643U,
			// Token: 0x04000110 RID: 272
			PipeNotAvailable,
			// Token: 0x04000111 RID: 273
			InvalidPipeState,
			// Token: 0x04000112 RID: 274
			PipeBusy,
			// Token: 0x04000113 RID: 275
			IllegalFunction,
			// Token: 0x04000114 RID: 276
			PipeDisconnected,
			// Token: 0x04000115 RID: 277
			PipeClosing,
			// Token: 0x04000116 RID: 278
			PipeConnected,
			// Token: 0x04000117 RID: 279
			PipeListening,
			// Token: 0x04000118 RID: 280
			InvalidReadMode,
			// Token: 0x04000119 RID: 281
			IoTimeout,
			// Token: 0x0400011A RID: 282
			FileForcedClosed,
			// Token: 0x0400011B RID: 283
			ProfilingNotStarted,
			// Token: 0x0400011C RID: 284
			ProfilingNotStopped,
			// Token: 0x0400011D RID: 285
			NotSameDevice = 3221225684U,
			// Token: 0x0400011E RID: 286
			FileRenamed,
			// Token: 0x0400011F RID: 287
			CantWait = 3221225688U,
			// Token: 0x04000120 RID: 288
			PipeEmpty,
			// Token: 0x04000121 RID: 289
			CantTerminateSelf = 3221225691U,
			// Token: 0x04000122 RID: 290
			InternalError = 3221225701U,
			// Token: 0x04000123 RID: 291
			InvalidParameter1 = 3221225711U,
			// Token: 0x04000124 RID: 292
			InvalidParameter2,
			// Token: 0x04000125 RID: 293
			InvalidParameter3,
			// Token: 0x04000126 RID: 294
			InvalidParameter4,
			// Token: 0x04000127 RID: 295
			InvalidParameter5,
			// Token: 0x04000128 RID: 296
			InvalidParameter6,
			// Token: 0x04000129 RID: 297
			InvalidParameter7,
			// Token: 0x0400012A RID: 298
			InvalidParameter8,
			// Token: 0x0400012B RID: 299
			InvalidParameter9,
			// Token: 0x0400012C RID: 300
			InvalidParameter10,
			// Token: 0x0400012D RID: 301
			InvalidParameter11,
			// Token: 0x0400012E RID: 302
			InvalidParameter12,
			// Token: 0x0400012F RID: 303
			MappedFileSizeZero = 3221225758U,
			// Token: 0x04000130 RID: 304
			TooManyOpenedFiles,
			// Token: 0x04000131 RID: 305
			Cancelled,
			// Token: 0x04000132 RID: 306
			CannotDelete,
			// Token: 0x04000133 RID: 307
			InvalidComputerName,
			// Token: 0x04000134 RID: 308
			FileDeleted,
			// Token: 0x04000135 RID: 309
			SpecialAccount,
			// Token: 0x04000136 RID: 310
			SpecialGroup,
			// Token: 0x04000137 RID: 311
			SpecialUser,
			// Token: 0x04000138 RID: 312
			MembersPrimaryGroup,
			// Token: 0x04000139 RID: 313
			FileClosed,
			// Token: 0x0400013A RID: 314
			TooManyThreads,
			// Token: 0x0400013B RID: 315
			ThreadNotInProcess,
			// Token: 0x0400013C RID: 316
			TokenAlreadyInUse,
			// Token: 0x0400013D RID: 317
			PagefileQuotaExceeded,
			// Token: 0x0400013E RID: 318
			CommitmentLimit,
			// Token: 0x0400013F RID: 319
			InvalidImageLeFormat,
			// Token: 0x04000140 RID: 320
			InvalidImageNotMz,
			// Token: 0x04000141 RID: 321
			InvalidImageProtect,
			// Token: 0x04000142 RID: 322
			InvalidImageWin16,
			// Token: 0x04000143 RID: 323
			LogonServer,
			// Token: 0x04000144 RID: 324
			DifferenceAtDc,
			// Token: 0x04000145 RID: 325
			SynchronizationRequired,
			// Token: 0x04000146 RID: 326
			DllNotFound,
			// Token: 0x04000147 RID: 327
			IoPrivilegeFailed = 3221225783U,
			// Token: 0x04000148 RID: 328
			OrdinalNotFound,
			// Token: 0x04000149 RID: 329
			EntryPointNotFound,
			// Token: 0x0400014A RID: 330
			ControlCExit,
			// Token: 0x0400014B RID: 331
			PortNotSet = 3221226323U,
			// Token: 0x0400014C RID: 332
			DebuggerInactive,
			// Token: 0x0400014D RID: 333
			CallbackBypass = 3221226755U,
			// Token: 0x0400014E RID: 334
			PortClosed = 3221227264U,
			// Token: 0x0400014F RID: 335
			MessageLost,
			// Token: 0x04000150 RID: 336
			InvalidMessage,
			// Token: 0x04000151 RID: 337
			RequestCanceled,
			// Token: 0x04000152 RID: 338
			RecursiveDispatch,
			// Token: 0x04000153 RID: 339
			LpcReceiveBufferExpected,
			// Token: 0x04000154 RID: 340
			LpcInvalidConnectionUsage,
			// Token: 0x04000155 RID: 341
			LpcRequestsNotAllowed,
			// Token: 0x04000156 RID: 342
			ResourceInUse,
			// Token: 0x04000157 RID: 343
			ProcessIsProtected = 3221227282U,
			// Token: 0x04000158 RID: 344
			VolumeDirty = 3221227526U,
			// Token: 0x04000159 RID: 345
			FileCheckedOut = 3221227777U,
			// Token: 0x0400015A RID: 346
			CheckOutRequired,
			// Token: 0x0400015B RID: 347
			BadFileType,
			// Token: 0x0400015C RID: 348
			FileTooLarge,
			// Token: 0x0400015D RID: 349
			FormsAuthRequired,
			// Token: 0x0400015E RID: 350
			VirusInfected,
			// Token: 0x0400015F RID: 351
			VirusDeleted,
			// Token: 0x04000160 RID: 352
			TransactionalConflict = 3222863873U,
			// Token: 0x04000161 RID: 353
			InvalidTransaction,
			// Token: 0x04000162 RID: 354
			TransactionNotActive,
			// Token: 0x04000163 RID: 355
			TmInitializationFailed,
			// Token: 0x04000164 RID: 356
			RmNotActive,
			// Token: 0x04000165 RID: 357
			RmMetadataCorrupt,
			// Token: 0x04000166 RID: 358
			TransactionNotJoined,
			// Token: 0x04000167 RID: 359
			DirectoryNotRm,
			// Token: 0x04000168 RID: 360
			CouldNotResizeLog,
			// Token: 0x04000169 RID: 361
			TransactionsUnsupportedRemote,
			// Token: 0x0400016A RID: 362
			LogResizeInvalidSize,
			// Token: 0x0400016B RID: 363
			RemoteFileVersionMismatch,
			// Token: 0x0400016C RID: 364
			CrmProtocolAlreadyExists = 3222863887U,
			// Token: 0x0400016D RID: 365
			TransactionPropagationFailed,
			// Token: 0x0400016E RID: 366
			CrmProtocolNotFound,
			// Token: 0x0400016F RID: 367
			TransactionSuperiorExists,
			// Token: 0x04000170 RID: 368
			TransactionRequestNotValid,
			// Token: 0x04000171 RID: 369
			TransactionNotRequested,
			// Token: 0x04000172 RID: 370
			TransactionAlreadyAborted,
			// Token: 0x04000173 RID: 371
			TransactionAlreadyCommitted,
			// Token: 0x04000174 RID: 372
			TransactionInvalidMarshallBuffer,
			// Token: 0x04000175 RID: 373
			CurrentTransactionNotValid,
			// Token: 0x04000176 RID: 374
			LogGrowthFailed,
			// Token: 0x04000177 RID: 375
			ObjectNoLongerExists = 3222863905U,
			// Token: 0x04000178 RID: 376
			StreamMiniversionNotFound,
			// Token: 0x04000179 RID: 377
			StreamMiniversionNotValid,
			// Token: 0x0400017A RID: 378
			MiniversionInaccessibleFromSpecifiedTransaction,
			// Token: 0x0400017B RID: 379
			CantOpenMiniversionWithModifyIntent,
			// Token: 0x0400017C RID: 380
			CantCreateMoreStreamMiniversions,
			// Token: 0x0400017D RID: 381
			HandleNoLongerValid = 3222863912U,
			// Token: 0x0400017E RID: 382
			NoTxfMetadata,
			// Token: 0x0400017F RID: 383
			LogCorruptionDetected = 3222863920U,
			// Token: 0x04000180 RID: 384
			CantRecoverWithHandleOpen,
			// Token: 0x04000181 RID: 385
			RmDisconnected,
			// Token: 0x04000182 RID: 386
			EnlistmentNotSuperior,
			// Token: 0x04000183 RID: 387
			RecoveryNotNeeded,
			// Token: 0x04000184 RID: 388
			RmAlreadyStarted,
			// Token: 0x04000185 RID: 389
			FileIdentityNotPersistent,
			// Token: 0x04000186 RID: 390
			CantBreakTransactionalDependency,
			// Token: 0x04000187 RID: 391
			CantCrossRmBoundary,
			// Token: 0x04000188 RID: 392
			TxfDirNotEmpty,
			// Token: 0x04000189 RID: 393
			IndoubtTransactionsExist,
			// Token: 0x0400018A RID: 394
			TmVolatile,
			// Token: 0x0400018B RID: 395
			RollbackTimerExpired,
			// Token: 0x0400018C RID: 396
			TxfAttributeCorrupt,
			// Token: 0x0400018D RID: 397
			EfsNotAllowedInTransaction,
			// Token: 0x0400018E RID: 398
			TransactionalOpenNotAllowed,
			// Token: 0x0400018F RID: 399
			TransactedMappingUnsupportedRemote,
			// Token: 0x04000190 RID: 400
			TxfMetadataAlreadyPresent,
			// Token: 0x04000191 RID: 401
			TransactionScopeCallbacksNotSet,
			// Token: 0x04000192 RID: 402
			TransactionRequiredPromotion,
			// Token: 0x04000193 RID: 403
			CannotExecuteFileInTransaction,
			// Token: 0x04000194 RID: 404
			TransactionsNotFrozen,
			// Token: 0x04000195 RID: 405
			MaximumNtStatus = 4294967295U
		}

		// Token: 0x02000009 RID: 9
		internal enum MINIDUMP_TYPE
		{
			// Token: 0x04000197 RID: 407
			MiniDumpNormal,
			// Token: 0x04000198 RID: 408
			MiniDumpWithDataSegs,
			// Token: 0x04000199 RID: 409
			MiniDumpWithFullMemory,
			// Token: 0x0400019A RID: 410
			MiniDumpWithHandleData = 4,
			// Token: 0x0400019B RID: 411
			MiniDumpFilterMemory = 8,
			// Token: 0x0400019C RID: 412
			MiniDumpScanMemory = 16,
			// Token: 0x0400019D RID: 413
			MiniDumpWithUnloadedModules = 32,
			// Token: 0x0400019E RID: 414
			MiniDumpWithIndirectlyReferencedMemory = 64,
			// Token: 0x0400019F RID: 415
			MiniDumpFilterModulePaths = 128,
			// Token: 0x040001A0 RID: 416
			MiniDumpWithProcessThreadData = 256,
			// Token: 0x040001A1 RID: 417
			MiniDumpWithPrivateReadWriteMemory = 512,
			// Token: 0x040001A2 RID: 418
			MiniDumpWithoutOptionalData = 1024,
			// Token: 0x040001A3 RID: 419
			MiniDumpWithFullMemoryInfo = 2048,
			// Token: 0x040001A4 RID: 420
			MiniDumpWithThreadInfo = 4096,
			// Token: 0x040001A5 RID: 421
			MiniDumpWithCodeSegs = 8192
		}

		// Token: 0x0200000A RID: 10
		[Flags]
		public enum MemoryProtection : uint
		{
			// Token: 0x040001A7 RID: 423
			Execute = 16U,
			// Token: 0x040001A8 RID: 424
			ExecuteRead = 32U,
			// Token: 0x040001A9 RID: 425
			ExecuteReadWrite = 64U,
			// Token: 0x040001AA RID: 426
			ExecuteWriteCopy = 128U,
			// Token: 0x040001AB RID: 427
			NoAccess = 1U,
			// Token: 0x040001AC RID: 428
			ReadOnly = 2U,
			// Token: 0x040001AD RID: 429
			ReadWrite = 4U,
			// Token: 0x040001AE RID: 430
			WriteCopy = 8U,
			// Token: 0x040001AF RID: 431
			GuardModifierflag = 256U,
			// Token: 0x040001B0 RID: 432
			NoCacheModifierflag = 512U,
			// Token: 0x040001B1 RID: 433
			WriteCombineModifierflag = 1024U
		}

		// Token: 0x0200000B RID: 11
		[Flags]
		public enum ThreadAccess
		{
			// Token: 0x040001B3 RID: 435
			TERMINATE = 1,
			// Token: 0x040001B4 RID: 436
			SUSPEND_RESUME = 2,
			// Token: 0x040001B5 RID: 437
			GET_CONTEXT = 8,
			// Token: 0x040001B6 RID: 438
			SET_CONTEXT = 16,
			// Token: 0x040001B7 RID: 439
			SET_INFORMATION = 32,
			// Token: 0x040001B8 RID: 440
			QUERY_INFORMATION = 64,
			// Token: 0x040001B9 RID: 441
			SET_THREAD_TOKEN = 128,
			// Token: 0x040001BA RID: 442
			IMPERSONATE = 256,
			// Token: 0x040001BB RID: 443
			DIRECT_IMPERSONATION = 512
		}

		// Token: 0x0200000C RID: 12
		public struct SYSTEM_INFO
		{
			// Token: 0x040001BC RID: 444
			public ushort processorArchitecture;

			// Token: 0x040001BD RID: 445
			private ushort reserved;

			// Token: 0x040001BE RID: 446
			public uint pageSize;

			// Token: 0x040001BF RID: 447
			public UIntPtr minimumApplicationAddress;

			// Token: 0x040001C0 RID: 448
			public UIntPtr maximumApplicationAddress;

			// Token: 0x040001C1 RID: 449
			public IntPtr activeProcessorMask;

			// Token: 0x040001C2 RID: 450
			public uint numberOfProcessors;

			// Token: 0x040001C3 RID: 451
			public uint processorType;

			// Token: 0x040001C4 RID: 452
			public uint allocationGranularity;

			// Token: 0x040001C5 RID: 453
			public ushort processorLevel;

			// Token: 0x040001C6 RID: 454
			public ushort processorRevision;
		}

		// Token: 0x0200000D RID: 13
		public struct MEMORY_BASIC_INFORMATION32
		{
			// Token: 0x040001C7 RID: 455
			public UIntPtr BaseAddress;

			// Token: 0x040001C8 RID: 456
			public UIntPtr AllocationBase;

			// Token: 0x040001C9 RID: 457
			public uint AllocationProtect;

			// Token: 0x040001CA RID: 458
			public uint RegionSize;

			// Token: 0x040001CB RID: 459
			public uint State;

			// Token: 0x040001CC RID: 460
			public uint Protect;

			// Token: 0x040001CD RID: 461
			public uint Type;
		}

		// Token: 0x0200000E RID: 14
		public struct MEMORY_BASIC_INFORMATION64
		{
			// Token: 0x040001CE RID: 462
			public UIntPtr BaseAddress;

			// Token: 0x040001CF RID: 463
			public UIntPtr AllocationBase;

			// Token: 0x040001D0 RID: 464
			public uint AllocationProtect;

			// Token: 0x040001D1 RID: 465
			public uint __alignment1;

			// Token: 0x040001D2 RID: 466
			public ulong RegionSize;

			// Token: 0x040001D3 RID: 467
			public uint State;

			// Token: 0x040001D4 RID: 468
			public uint Protect;

			// Token: 0x040001D5 RID: 469
			public uint Type;

			// Token: 0x040001D6 RID: 470
			public uint __alignment2;
		}

		// Token: 0x0200000F RID: 15
		public struct ProcessEntry32
		{
			// Token: 0x040001D7 RID: 471
			public uint dwSize;

			// Token: 0x040001D8 RID: 472
			public uint cntUsage;

			// Token: 0x040001D9 RID: 473
			public uint th32ProcessID;

			// Token: 0x040001DA RID: 474
			public IntPtr th32DefaultHeapID;

			// Token: 0x040001DB RID: 475
			public uint th32ModuleID;

			// Token: 0x040001DC RID: 476
			public uint cntThreads;

			// Token: 0x040001DD RID: 477
			public uint th32ParentProcessID;

			// Token: 0x040001DE RID: 478
			public int pcPriClassBase;

			// Token: 0x040001DF RID: 479
			public uint dwFlags;

			// Token: 0x040001E0 RID: 480
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
			public string szExeFile;
		}

		// Token: 0x02000010 RID: 16
		public struct MEMORY_BASIC_INFORMATION
		{
			// Token: 0x040001E1 RID: 481
			public UIntPtr BaseAddress;

			// Token: 0x040001E2 RID: 482
			public UIntPtr AllocationBase;

			// Token: 0x040001E3 RID: 483
			public uint AllocationProtect;

			// Token: 0x040001E4 RID: 484
			public long RegionSize;

			// Token: 0x040001E5 RID: 485
			public uint State;

			// Token: 0x040001E6 RID: 486
			public uint Protect;

			// Token: 0x040001E7 RID: 487
			public uint Type;
		}

		// Token: 0x02000011 RID: 17
		[Flags]
		public enum ProcessAccessFlags
		{
			// Token: 0x040001E9 RID: 489
			All = 2035711,
			// Token: 0x040001EA RID: 490
			Terminate = 1,
			// Token: 0x040001EB RID: 491
			CreateThread = 2,
			// Token: 0x040001EC RID: 492
			VirtualMemoryOperation = 8,
			// Token: 0x040001ED RID: 493
			VirtualMemoryRead = 16,
			// Token: 0x040001EE RID: 494
			VirtualMemoryWrite = 32,
			// Token: 0x040001EF RID: 495
			DuplicateHandle = 64,
			// Token: 0x040001F0 RID: 496
			CreateProcess = 128,
			// Token: 0x040001F1 RID: 497
			SetQuota = 256,
			// Token: 0x040001F2 RID: 498
			SetInformation = 512,
			// Token: 0x040001F3 RID: 499
			QueryInformation = 1024,
			// Token: 0x040001F4 RID: 500
			QueryLimitedInformation = 4096,
			// Token: 0x040001F5 RID: 501
			Synchronize = 1048576
		}

		// Token: 0x02000012 RID: 18
		public struct OBJECT_ATTRIBUTES
		{
			// Token: 0x040001F6 RID: 502
			private int Length;

			// Token: 0x040001F7 RID: 503
			private IntPtr RootDirectory;

			// Token: 0x040001F8 RID: 504
			private IntPtr ObjectName;

			// Token: 0x040001F9 RID: 505
			private uint Attributes;

			// Token: 0x040001FA RID: 506
			private IntPtr SecurityDescriptor;

			// Token: 0x040001FB RID: 507
			private IntPtr SecurityQualityOfService;
		}

		// Token: 0x02000013 RID: 19
		public struct CLIENT_ID
		{
			// Token: 0x040001FC RID: 508
			private IntPtr UniqueProcess;

			// Token: 0x040001FD RID: 509
			private IntPtr UniqueThread;
		}
	}
}
