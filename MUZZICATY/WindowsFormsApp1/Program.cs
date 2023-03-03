using System;
using System.Windows.Forms;

namespace WindowsFormsApp1
{
	// Token: 0x02000005 RID: 5
	internal static class Program
	{
		// Token: 0x060000BB RID: 187 RVA: 0x00006F1C File Offset: 0x0000511C
		[STAThread]
		private static void Main()
		{
			Application.EnableVisualStyles();
			Application.SetCompatibleTextRenderingDefault(false);
			Application.Run(new Form1());
		}
	}
}
