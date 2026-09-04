using System;
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
        AiPage.Visibility = tag == "ai" ? Visibility.Visible : Visibility.Collapsed;
        AppearancePage.Visibility = tag == "appearance" ? Visibility.Visible : Visibility.Collapsed;
        ScanningPage.Visibility = tag == "scanning" ? Visibility.Visible : Visibility.Collapsed;
        StoragePage.Visibility = tag == "storage" ? Visibility.Visible : Visibility.Collapsed;
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
