using System;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace NetControl;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            bool isAutoStart = desktop.Args != null &&
                               Array.Exists(desktop.Args, a => string.Equals(a, "--autostart", StringComparison.OrdinalIgnoreCase));
            desktop.MainWindow = new MainWindow(isAutoStart);
        }

        base.OnFrameworkInitializationCompleted();
    }
}