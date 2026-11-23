using System;
using System.Diagnostics;
using System.IO;
using System.Security;
using System.Text;

namespace NetControl
{
    /// <summary>
    /// Mengelola pendaftaran Autostart NetControl pada Windows Task Scheduler (Run with highest privileges)
    /// maupun autostart desktop entry di Linux tanpa memunculkan jendela terminal.
    /// </summary>
    public static class AutostartManager
    {
        public const string WindowsTaskName = "NetControl_Autostart";

        public static string BuildWindowsTaskXml(string command, string arguments, string workingDirectory, string userId)
        {
            string escCmd = SecurityElement.Escape(command ?? string.Empty) ?? string.Empty;
            string escArgs = SecurityElement.Escape(arguments ?? string.Empty) ?? string.Empty;
            string escWorkDir = SecurityElement.Escape(workingDirectory ?? string.Empty) ?? string.Empty;
            string escUser = SecurityElement.Escape(userId ?? string.Empty) ?? string.Empty;

            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"UTF-16\"?>");
            sb.AppendLine("<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">");
            sb.AppendLine("  <RegistrationInfo>");
            sb.AppendLine("    <Description>Menjalankan NetControl dengan hak Administrator saat Windows login.</Description>");
            sb.AppendLine("  </RegistrationInfo>");
            sb.AppendLine("  <Triggers>");
            sb.AppendLine("    <LogonTrigger>");
            sb.AppendLine("      <Enabled>true</Enabled>");
            sb.AppendLine("      <Delay>PT5S</Delay>");
            if (!string.IsNullOrWhiteSpace(escUser))
            {
                sb.AppendLine($"      <UserId>{escUser}</UserId>");
            }
            sb.AppendLine("    </LogonTrigger>");
            sb.AppendLine("  </Triggers>");
            sb.AppendLine("  <Principals>");
            sb.AppendLine("    <Principal id=\"Author\">");
            if (!string.IsNullOrWhiteSpace(escUser))
            {
                sb.AppendLine($"      <UserId>{escUser}</UserId>");
            }
            sb.AppendLine("      <LogonType>InteractiveToken</LogonType>");
            sb.AppendLine("      <RunLevel>HighestAvailable</RunLevel>");
            sb.AppendLine("    </Principal>");
            sb.AppendLine("  </Principals>");
            sb.AppendLine("  <Settings>");
            sb.AppendLine("    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
            sb.AppendLine("    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>");
            sb.AppendLine("    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>");
            sb.AppendLine("    <AllowHardTerminate>true</AllowHardTerminate>");
            sb.AppendLine("    <StartWhenAvailable>true</StartWhenAvailable>");
            sb.AppendLine("    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>");
            sb.AppendLine("    <IdleSettings>");
            sb.AppendLine("      <StopOnIdleEnd>false</StopOnIdleEnd>");
            sb.AppendLine("      <RestartOnIdle>false</RestartOnIdle>");
            sb.AppendLine("    </IdleSettings>");
            sb.AppendLine("    <AllowStartOnDemand>true</AllowStartOnDemand>");
            sb.AppendLine("    <Enabled>true</Enabled>");
            sb.AppendLine("    <Hidden>false</Hidden>");
            sb.AppendLine("    <RunOnlyIfIdle>false</RunOnlyIfIdle>");
            sb.AppendLine("    <WakeToRun>false</WakeToRun>");
            sb.AppendLine("    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
            sb.AppendLine("    <Priority>7</Priority>");
            sb.AppendLine("  </Settings>");
            sb.AppendLine("  <Actions Context=\"Author\">");
            sb.AppendLine("    <Exec>");
            sb.AppendLine($"      <Command>{escCmd}</Command>");
            if (!string.IsNullOrWhiteSpace(escArgs))
            {
                sb.AppendLine($"      <Arguments>{escArgs}</Arguments>");
            }
            if (!string.IsNullOrWhiteSpace(escWorkDir))
            {
                sb.AppendLine($"      <WorkingDirectory>{escWorkDir}</WorkingDirectory>");
            }
            sb.AppendLine("    </Exec>");
            sb.AppendLine("  </Actions>");
            sb.AppendLine("</Task>");

            return sb.ToString();
        }

        public static (string Command, string Arguments, string WorkingDirectory) ResolveLaunchCommand()
        {
            string baseDir = AppContext.BaseDirectory?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) ?? string.Empty;

            if (OperatingSystem.IsWindows())
            {
                string exeCandidate = Path.Combine(baseDir, "NetControl.exe");
                if (File.Exists(exeCandidate))
                {
                    return (exeCandidate, "--autostart", baseDir);
                }
            }

            string procPath = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(procPath) &&
                File.Exists(procPath) &&
                !procPath.EndsWith("dotnet.exe", StringComparison.OrdinalIgnoreCase) &&
                !procPath.EndsWith("/dotnet", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Path.GetFileName(procPath), "dotnet", StringComparison.OrdinalIgnoreCase))
            {
                return (procPath, "--autostart", baseDir);
            }

            string dllPath = Path.Combine(baseDir, "NetControl.dll");
            return (procPath ?? "dotnet", $"\"{dllPath}\" --autostart", baseDir);
        }

        public static bool IsAutostartRegistered()
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    using var proc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "schtasks",
                        Arguments = $"/Query /TN \"{WindowsTaskName}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    });
                    if (proc == null) return false;
                    proc.WaitForExit(3000);
                    return proc.ExitCode == 0;
                }

                if (OperatingSystem.IsLinux())
                {
                    return File.Exists(GetLinuxDesktopEntryPath());
                }
            }
            catch
            {
                // Best-effort query
            }

            return false;
        }

        public static (bool Success, string Message) SetAutostart(bool enable)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    if (!PrivilegeDetector.IsElevated())
                    {
                        return (false, "Jalankan NetControl sebagai Administrator untuk mengubah Autostart Windows.");
                    }

                    if (enable)
                    {
                        string userId = !string.IsNullOrEmpty(Environment.UserDomainName)
                            ? $"{Environment.UserDomainName}\\{Environment.UserName}"
                            : Environment.UserName;

                        var (cmd, args, workDir) = ResolveLaunchCommand();
                        string xml = BuildWindowsTaskXml(cmd, args, workDir, userId);
                        string tempXml = Path.Combine(Path.GetTempPath(), $"netcontrol_task_{Guid.NewGuid():N}.xml");

                        try
                        {
                            File.WriteAllText(tempXml, xml, Encoding.Unicode);

                            using var proc = Process.Start(new ProcessStartInfo
                            {
                                FileName = "schtasks",
                                Arguments = $"/Create /TN \"{WindowsTaskName}\" /XML \"{tempXml}\" /F",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            });
                            if (proc == null)
                            {
                                return (false, "Gagal menjalankan schtasks untuk mendaftarkan Autostart.");
                            }

                            string stdout = proc.StandardOutput.ReadToEnd();
                            string stderr = proc.StandardError.ReadToEnd();
                            proc.WaitForExit(5000);

                            if (proc.ExitCode == 0)
                            {
                                return (true, "Autostart Windows berhasil didaftarkan (Task Scheduler).");
                            }

                            string err = !string.IsNullOrWhiteSpace(stderr) ? stderr.Trim() : stdout.Trim();
                            return (false, $"Gagal mendaftarkan Task Scheduler: {err}");
                        }
                        finally
                        {
                            try { if (File.Exists(tempXml)) File.Delete(tempXml); } catch { }
                        }
                    }
                    else
                    {
                        using var proc = Process.Start(new ProcessStartInfo
                        {
                            FileName = "schtasks",
                            Arguments = $"/Delete /TN \"{WindowsTaskName}\" /F",
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        });
                        if (proc == null)
                        {
                            return (false, "Gagal menjalankan schtasks untuk menghapus Autostart.");
                        }

                        string stdout = proc.StandardOutput.ReadToEnd();
                        string stderr = proc.StandardError.ReadToEnd();
                        proc.WaitForExit(5000);

                        if (proc.ExitCode == 0 || !IsAutostartRegistered())
                        {
                            return (true, "Autostart Windows dinonaktifkan.");
                        }

                        string err = !string.IsNullOrWhiteSpace(stderr) ? stderr.Trim() : stdout.Trim();
                        return (false, $"Gagal menghapus task: {err}");
                    }
                }

                if (OperatingSystem.IsLinux())
                {
                    string path = GetLinuxDesktopEntryPath();
                    if (enable)
                    {
                        string dir = Path.GetDirectoryName(path);
                        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                        var (cmd, args, _) = ResolveLaunchCommand();
                        string content = string.Join('\n', new[]
                        {
                            "[Desktop Entry]",
                            "Type=Application",
                            "Name=NetControl",
                            $"Exec=\"{cmd}\" {args}",
                            "Terminal=false",
                            "X-GNOME-Autostart-enabled=true",
                            string.Empty
                        });
                        File.WriteAllText(path, content);
                        return (true, "Autostart Linux berhasil didaftarkan.");
                    }
                    else
                    {
                        if (File.Exists(path)) File.Delete(path);
                        return (true, "Autostart Linux dinonaktifkan.");
                    }
                }

                return (false, "Autostart otomatis belum didukung pada sistem operasi ini.");
            }
            catch (Exception ex)
            {
                return (false, $"Gagal mengatur Autostart: {ex.Message}");
            }
        }

        private static string GetLinuxDesktopEntryPath()
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, ".config", "autostart", "netcontrol.desktop");
        }
    }
}
