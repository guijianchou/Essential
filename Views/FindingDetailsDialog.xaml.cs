using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.Views;

public sealed partial class FindingDetailsDialog : ContentDialog
{
    public AuditIssueEnhanced Issue { get; }
    public List<KeyValuePair<string, string>> EvidenceRows { get; } = new();
    public string DescriptionText => string.IsNullOrWhiteSpace(Issue.Description)
        ? AppText.Get("No additional description was returned.") : Issue.Description;
    public string EventText => string.IsNullOrWhiteSpace(Issue.EventDescription)
        ? AppText.Get("The original event description was not stored.") : Issue.EventDescription;
    public string AdditionalText => string.IsNullOrWhiteSpace(Issue.EventAdditionalData)
        ? AppText.Get("No additional event data was recorded.") : Issue.EventAdditionalData;

    public FindingDetailsDialog(AuditIssueEnhanced issue, XamlRoot root, ElementTheme theme)
    {
        Issue = issue;
        AddEvidence("Analysis model", issue.ModelLabel);
        AddEvidence("Optimization", issue.ModelHistoryText);
        AddEvidence("Event ID", issue.EventId);
        AddEvidence("Log", issue.LogName);
        AddEvidence("Source", issue.Source);
        AddEvidence("Record", issue.EventRecordId);
        AddEvidence("Account", issue.UserName);
        AddEvidence("IP address", issue.IpAddress);
        AddEvidence("Affected", issue.Affected);
        AddEvidence("Observed", issue.EventTimestamp == default
            ? issue.EvidenceTimeText : issue.EventTimestamp.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", AppText.Culture));
        AddEvidence("Related events", issue.OccurrenceSummaryText);
        AddEvidence("Observation range", issue.EvidenceTimeText);

        InitializeComponent();
        XamlRoot = root;
        RequestedTheme = theme;
        LayoutRoot.Width = Math.Clamp(root.Size.Width - 160, 320, 780);
        LayoutRoot.Height = Math.Clamp(root.Size.Height - 250, 280, 460);
        string severity = issue.IsHigh ? "High" : issue.IsMedium ? "Medium" : "Low";
        SeverityBadge.Background = ThemeResources.GetBrush(this, "ControlFillColorSecondaryBrush");
        SeverityText.Foreground = ThemeResources.GetBrush(this, $"Severity{severity}TextBrush");
    }

    private void AddEvidence(string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            EvidenceRows.Add(new KeyValuePair<string, string>(AppText.Get(label), value));
    }

    private void OnCopyClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var data = new DataPackage();
            data.SetText(string.Join(Environment.NewLine + Environment.NewLine,
                Issue.DisplayTitle, DescriptionText,
                AppText.Get("Why this was flagged") + Environment.NewLine + Issue.PriorityReasonText,
                AppText.Get("Recommended action") + Environment.NewLine + Issue.PriorityActionText,
                string.Join(Environment.NewLine, EvidenceRows.Select(row => $"{row.Key}: {row.Value}")),
                AppText.Get("Original event") + Environment.NewLine + EventText,
                AppText.Get("Additional event data") + Environment.NewLine + AdditionalText));
            Clipboard.SetContent(data);
            CopyStatus.Text = AppText.Get("Copied");
        }
        catch (Exception ex)
        {
            CopyStatus.Text = AppText.Format("Copy failed: {0}", ex.Message);
            ToolTipService.SetToolTip(CopyStatus, CopyStatus.Text);
        }
    }
}
