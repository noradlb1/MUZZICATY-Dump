namespace WindowsFormsApp1
{
	// Token: 0x02000004 RID: 4
	public partial class Form1 : global::System.Windows.Forms.Form
	{
		// Token: 0x060000B5 RID: 181 RVA: 0x00005D10 File Offset: 0x00003F10
		protected override void Dispose(bool disposing)
		{
			bool flag = disposing && this.components != null;
			if (flag)
			{
				this.components.Dispose();
			}
			base.Dispose(disposing);
		}

		// Token: 0x060000B6 RID: 182 RVA: 0x00005D48 File Offset: 0x00003F48
		private void InitializeComponent()
		{
			global::System.ComponentModel.ComponentResourceManager componentResourceManager = new global::System.ComponentModel.ComponentResourceManager(typeof(global::WindowsFormsApp1.Form1));
			this.siticoneRoundedGradientButton5 = new global::Siticone.UI.WinForms.SiticoneRoundedGradientButton();
			this.label2 = new global::System.Windows.Forms.Label();
			this.label4 = new global::System.Windows.Forms.Label();
			this.siticoneRoundedComboBox1 = new global::Siticone.UI.WinForms.SiticoneRoundedComboBox();
			this.siticoneRoundedGradientButton3 = new global::Siticone.UI.WinForms.SiticoneRoundedGradientButton();
			this.siticoneRoundedGradientButton1 = new global::Siticone.UI.WinForms.SiticoneRoundedGradientButton();
			this.siticoneRoundedGradientButton2 = new global::Siticone.UI.WinForms.SiticoneRoundedGradientButton();
			this.siticoneRoundedGradientButton6 = new global::Siticone.UI.WinForms.SiticoneRoundedGradientButton();
			base.SuspendLayout();
			this.siticoneRoundedGradientButton5.CheckedState.Parent = this.siticoneRoundedGradientButton5;
			this.siticoneRoundedGradientButton5.CustomImages.Parent = this.siticoneRoundedGradientButton5;
			this.siticoneRoundedGradientButton5.Font = new global::System.Drawing.Font("Segoe UI", 9f);
			this.siticoneRoundedGradientButton5.ForeColor = global::System.Drawing.Color.White;
			this.siticoneRoundedGradientButton5.HoveredState.Parent = this.siticoneRoundedGradientButton5;
			this.siticoneRoundedGradientButton5.Location = new global::System.Drawing.Point(163, 115);
			this.siticoneRoundedGradientButton5.Name = "siticoneRoundedGradientButton5";
			this.siticoneRoundedGradientButton5.ShadowDecoration.Parent = this.siticoneRoundedGradientButton5;
			this.siticoneRoundedGradientButton5.Size = new global::System.Drawing.Size(149, 25);
			this.siticoneRoundedGradientButton5.TabIndex = 57;
			this.siticoneRoundedGradientButton5.Text = "Compare";
			this.siticoneRoundedGradientButton5.Click += new global::System.EventHandler(this.siticoneRoundedGradientButton5_Click);
			this.label2.AutoSize = true;
			this.label2.Font = new global::System.Drawing.Font("Tahoma", 9f, global::System.Drawing.FontStyle.Regular, global::System.Drawing.GraphicsUnit.Point, 0);
			this.label2.Location = new global::System.Drawing.Point(9, 124);
			this.label2.Name = "label2";
			this.label2.Size = new global::System.Drawing.Size(48, 14);
			this.label2.TabIndex = 42;
			this.label2.Text = "status :";
			this.label4.AutoSize = true;
			this.label4.Font = new global::System.Drawing.Font("Tahoma", 9f, global::System.Drawing.FontStyle.Regular, global::System.Drawing.GraphicsUnit.Point, 0);
			this.label4.Location = new global::System.Drawing.Point(63, 124);
			this.label4.Name = "label4";
			this.label4.Size = new global::System.Drawing.Size(0, 14);
			this.label4.TabIndex = 44;
			this.label4.Click += new global::System.EventHandler(this.label4_Click);
			this.siticoneRoundedComboBox1.BackColor = global::System.Drawing.Color.Transparent;
			this.siticoneRoundedComboBox1.DrawMode = global::System.Windows.Forms.DrawMode.OwnerDrawFixed;
			this.siticoneRoundedComboBox1.DropDownStyle = global::System.Windows.Forms.ComboBoxStyle.DropDownList;
			this.siticoneRoundedComboBox1.Font = new global::System.Drawing.Font("Segoe UI", 8.25f, global::System.Drawing.FontStyle.Regular, global::System.Drawing.GraphicsUnit.Point, 0);
			this.siticoneRoundedComboBox1.ForeColor = global::System.Drawing.Color.FromArgb(68, 88, 112);
			this.siticoneRoundedComboBox1.FormattingEnabled = true;
			this.siticoneRoundedComboBox1.HoveredState.Parent = this.siticoneRoundedComboBox1;
			this.siticoneRoundedComboBox1.ItemHeight = 30;
			this.siticoneRoundedComboBox1.Items.AddRange(new object[]
			{
				"Gameloop",
				"SmartGaGa"
			});
			this.siticoneRoundedComboBox1.ItemsAppearance.Parent = this.siticoneRoundedComboBox1;
			this.siticoneRoundedComboBox1.Location = new global::System.Drawing.Point(163, 12);
			this.siticoneRoundedComboBox1.Name = "siticoneRoundedComboBox1";
			this.siticoneRoundedComboBox1.ShadowDecoration.BorderRadius = 4;
			this.siticoneRoundedComboBox1.ShadowDecoration.Parent = this.siticoneRoundedComboBox1;
			this.siticoneRoundedComboBox1.Size = new global::System.Drawing.Size(149, 36);
			this.siticoneRoundedComboBox1.TabIndex = 50;
			this.siticoneRoundedComboBox1.SelectedIndexChanged += new global::System.EventHandler(this.siticoneRoundedComboBox1_SelectedIndexChanged);
			this.siticoneRoundedGradientButton3.CheckedState.Parent = this.siticoneRoundedGradientButton3;
			this.siticoneRoundedGradientButton3.CustomImages.Parent = this.siticoneRoundedGradientButton3;
			this.siticoneRoundedGradientButton3.Font = new global::System.Drawing.Font("Segoe UI", 9f);
			this.siticoneRoundedGradientButton3.ForeColor = global::System.Drawing.Color.White;
			this.siticoneRoundedGradientButton3.HoveredState.Parent = this.siticoneRoundedGradientButton3;
			this.siticoneRoundedGradientButton3.Location = new global::System.Drawing.Point(163, 54);
			this.siticoneRoundedGradientButton3.Name = "siticoneRoundedGradientButton3";
			this.siticoneRoundedGradientButton3.ShadowDecoration.BorderRadius = 0;
			this.siticoneRoundedGradientButton3.ShadowDecoration.Depth = 2;
			this.siticoneRoundedGradientButton3.ShadowDecoration.Enabled = true;
			this.siticoneRoundedGradientButton3.ShadowDecoration.Parent = this.siticoneRoundedGradientButton3;
			this.siticoneRoundedGradientButton3.Size = new global::System.Drawing.Size(149, 25);
			this.siticoneRoundedGradientButton3.TabIndex = 55;
			this.siticoneRoundedGradientButton3.Text = "Moded";
			this.siticoneRoundedGradientButton3.Click += new global::System.EventHandler(this.siticoneRoundedGradientButton3_Click);
			this.siticoneRoundedGradientButton1.BackColor = global::System.Drawing.Color.Transparent;
			this.siticoneRoundedGradientButton1.CheckedState.Parent = this.siticoneRoundedGradientButton1;
			this.siticoneRoundedGradientButton1.CustomImages.Parent = this.siticoneRoundedGradientButton1;
			this.siticoneRoundedGradientButton1.Font = new global::System.Drawing.Font("Segoe UI", 9f);
			this.siticoneRoundedGradientButton1.ForeColor = global::System.Drawing.Color.White;
			this.siticoneRoundedGradientButton1.HoveredState.Parent = this.siticoneRoundedGradientButton1;
			this.siticoneRoundedGradientButton1.Location = new global::System.Drawing.Point(12, 12);
			this.siticoneRoundedGradientButton1.Name = "siticoneRoundedGradientButton1";
			this.siticoneRoundedGradientButton1.ShadowDecoration.Parent = this.siticoneRoundedGradientButton1;
			this.siticoneRoundedGradientButton1.Size = new global::System.Drawing.Size(89, 23);
			this.siticoneRoundedGradientButton1.TabIndex = 58;
			this.siticoneRoundedGradientButton1.Text = "Load Drv";
			this.siticoneRoundedGradientButton1.Click += new global::System.EventHandler(this.siticoneRoundedGradientButton1_Click_1);
			this.siticoneRoundedGradientButton2.CheckedState.Parent = this.siticoneRoundedGradientButton2;
			this.siticoneRoundedGradientButton2.CustomImages.Parent = this.siticoneRoundedGradientButton2;
			this.siticoneRoundedGradientButton2.Font = new global::System.Drawing.Font("Segoe UI", 9f);
			this.siticoneRoundedGradientButton2.ForeColor = global::System.Drawing.Color.White;
			this.siticoneRoundedGradientButton2.HoveredState.Parent = this.siticoneRoundedGradientButton2;
			this.siticoneRoundedGradientButton2.Location = new global::System.Drawing.Point(12, 41);
			this.siticoneRoundedGradientButton2.Name = "siticoneRoundedGradientButton2";
			this.siticoneRoundedGradientButton2.ShadowDecoration.Parent = this.siticoneRoundedGradientButton2;
			this.siticoneRoundedGradientButton2.Size = new global::System.Drawing.Size(89, 23);
			this.siticoneRoundedGradientButton2.TabIndex = 59;
			this.siticoneRoundedGradientButton2.Text = "Unload Drv";
			this.siticoneRoundedGradientButton2.Click += new global::System.EventHandler(this.siticoneRoundedGradientButton2_Click_1);
			this.siticoneRoundedGradientButton6.CheckedState.Parent = this.siticoneRoundedGradientButton6;
			this.siticoneRoundedGradientButton6.CustomImages.Parent = this.siticoneRoundedGradientButton6;
			this.siticoneRoundedGradientButton6.Font = new global::System.Drawing.Font("Segoe UI", 9f);
			this.siticoneRoundedGradientButton6.ForeColor = global::System.Drawing.Color.White;
			this.siticoneRoundedGradientButton6.HoveredState.Parent = this.siticoneRoundedGradientButton6;
			this.siticoneRoundedGradientButton6.Location = new global::System.Drawing.Point(163, 85);
			this.siticoneRoundedGradientButton6.Name = "siticoneRoundedGradientButton6";
			this.siticoneRoundedGradientButton6.ShadowDecoration.Parent = this.siticoneRoundedGradientButton6;
			this.siticoneRoundedGradientButton6.Size = new global::System.Drawing.Size(149, 25);
			this.siticoneRoundedGradientButton6.TabIndex = 61;
			this.siticoneRoundedGradientButton6.Text = "Original";
			this.siticoneRoundedGradientButton6.Click += new global::System.EventHandler(this.siticoneRoundedGradientButton6_Click);
			base.AutoScaleDimensions = new global::System.Drawing.SizeF(6f, 13f);
			base.AutoScaleMode = global::System.Windows.Forms.AutoScaleMode.Font;
			base.AutoSizeMode = global::System.Windows.Forms.AutoSizeMode.GrowAndShrink;
			this.BackColor = global::System.Drawing.Color.White;
			base.ClientSize = new global::System.Drawing.Size(320, 159);
			base.Controls.Add(this.siticoneRoundedGradientButton6);
			base.Controls.Add(this.siticoneRoundedGradientButton2);
			base.Controls.Add(this.siticoneRoundedGradientButton1);
			base.Controls.Add(this.siticoneRoundedGradientButton5);
			base.Controls.Add(this.siticoneRoundedGradientButton3);
			base.Controls.Add(this.label4);
			base.Controls.Add(this.siticoneRoundedComboBox1);
			base.Controls.Add(this.label2);
			base.Icon = (global::System.Drawing.Icon)componentResourceManager.GetObject("$this.Icon");
			base.MaximizeBox = false;
			base.Name = "Form1";
			base.SizeGripStyle = global::System.Windows.Forms.SizeGripStyle.Hide;
			this.Text = "MUZZICATY";
			base.Load += new global::System.EventHandler(this.Form1_Load);
			base.ResumeLayout(false);
			base.PerformLayout();
		}

		// Token: 0x0400003E RID: 62
		private global::System.ComponentModel.IContainer components = null;

		// Token: 0x0400003F RID: 63
		private global::Siticone.UI.WinForms.SiticoneRoundedComboBox siticoneRoundedComboBox1;

		// Token: 0x04000040 RID: 64
		private global::System.Windows.Forms.Label label4;

		// Token: 0x04000041 RID: 65
		private global::System.Windows.Forms.Label label2;

		// Token: 0x04000042 RID: 66
		private global::Siticone.UI.WinForms.SiticoneRoundedGradientButton siticoneRoundedGradientButton3;

		// Token: 0x04000043 RID: 67
		private global::Siticone.UI.WinForms.SiticoneRoundedGradientButton siticoneRoundedGradientButton5;

		// Token: 0x04000044 RID: 68
		private global::Siticone.UI.WinForms.SiticoneRoundedGradientButton siticoneRoundedGradientButton1;

		// Token: 0x04000045 RID: 69
		private global::Siticone.UI.WinForms.SiticoneRoundedGradientButton siticoneRoundedGradientButton2;

		// Token: 0x04000046 RID: 70
		private global::Siticone.UI.WinForms.SiticoneRoundedGradientButton siticoneRoundedGradientButton6;
	}
}
