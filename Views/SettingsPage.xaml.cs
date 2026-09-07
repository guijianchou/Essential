using System;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Views;

public sealed partial class SettingsPage : Page
{
    public ViewModels.SettingsViewModel ViewModel { get; }

    public SettingsPage()
    {
        ViewModel = App.GetService<ViewModels.SettingsViewModel>();
        InitializeComponent();
        DataContext = ViewModel;
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // "--section=ai" (used by tooling) opens a specific settings section.
        string? requestedSection = Environment.GetCommandLineArgs()
            .Select(argument => argument.Trim())
            .FirstOrDefault(argument => argument.StartsWith("--section=", StringComparison.OrdinalIgnoreCase))
            ?["--section=".Length..].ToLowerInvariant();
        if (requestedSection != null)
        {
            var requestedItem = NavView.MenuItems
                .OfType<NavigationViewItem>()
                .FirstOrDefault(item => string.Equals(item.Tag?.ToString(), requestedSection, StringComparison.OrdinalIgnoreCase));
            if (requestedItem != null)
            {
                NavView.SelectedItem = requestedItem;
                ShowSection(requestedSection);
                return;
            }
        }

        if (NavView.SelectedItem is NavigationViewItem selectedItem
            && selectedItem.Tag is string selectedTag)
        {
            ShowSection(selectedTag);
        }
        else if (NavView.MenuItems.Count > 0)
        {
            NavView.SelectedItem = NavView.MenuItems[0];
        }
    }

    private void OnNavViewSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is NavigationViewItem item && item.Tag is string tag)
        {
            ShowSection(tag);
        }
    }

    private void ShowSection(string tag)
    {
        if (ViewModel.IsAssistantMode && tag is "ai" or "optimization" or "scanning")
        {
            NavView.SelectedItem = NavView.MenuItems[0];
            tag = "mode";
        }
        ModePage.Visibility = tag == "mode" ? Visibility.Visible : Visibility.Collapsed;
        AiPage.Visibility = tag == "ai" ? Visibility.Visible : Visibility.Collapsed;
        OptimizationPage.Visibility = tag == "optimization" ? Visibility.Visible : Visibility.Collapsed;
        if (tag == "optimization") _ = ViewModel.RefreshOptimizationPreviewCommand.ExecuteAsync(null);
        AppearancePage.Visibility = tag == "appearance" ? Visibility.Visible : Visibility.Collapsed;
        ScanningPage.Visibility = tag == "scanning" ? Visibility.Visible : Visibility.Collapsed;
        StoragePage.Visibility = tag == "storage" ? Visibility.Visible : Visibility.Collapsed;
        if (tag == "storage") _ = ViewModel.UpdateDatabaseStatsCommand.ExecuteAsync(null);
        AboutPage.Visibility = tag == "about" ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnInfoBarClosed(InfoBar sender, object args)
    {
        ViewModel.ShowOperationStatus = false;
    }

    private void OnTargetPasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox passwordBox && passwordBox.DataContext is AiTarget target)
        {
            target.ApiKey = passwordBox.Password;
        }
    }

    private void OnRemoveTargetClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is AiTarget target)
        {
            ViewModel.RemoveTargetCommand.Execute(target);
        }
    }

    private void OnSetActiveTargetClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is AiTarget target)
        {
            ViewModel.SetActiveTargetCommand.Execute(target);
        }
    }

    private async void OnTestApiConnectionClicked(object sender, RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is AiTarget target)
        {
            await ViewModel.TestApiConnectionCommand.ExecuteAsync(target);
        }
    }
}
