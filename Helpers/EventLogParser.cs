using System;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Xml.Linq;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Helpers;

public static class EventLogParser
{
    public static SecurityEvent Parse(EventRecord eventRecord, string logName)
    {
        var securityEvent = new SecurityEvent
        {
            EventId = eventRecord.Id,
            EventRecordId = eventRecord.RecordId,
            Timestamp = (eventRecord.TimeCreated ?? DateTime.UtcNow).ToUniversalTime(),
            LogName = logName,
            Source = eventRecord.ProviderName ?? "Unknown",
            Description = eventRecord.FormatDescription() ?? $"Event ID {eventRecord.Id}",
            Severity = GetSeverityFromLevel(eventRecord.Level)
        };

        try
        {
            ApplyEventData(securityEvent, eventRecord.ToXml());
        }
        catch
        {
            // If property extraction fails, continue without it
        }

        return securityEvent;
    }

    private static void ApplyEventData(SecurityEvent securityEvent, string eventXml)
    {
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        var root = XDocument.Parse(eventXml).Root;
        var eventData = root?.Element(ns + "EventData");
        securityEvent.AdditionalData = (eventData ?? root?.Element(ns + "UserData"))?.ToString();
        if (eventData == null)
        {
            return;
        }

        // Field positions vary between event IDs and schema versions.
        var values = eventData.Elements(ns + "Data")
            .ToLookup(element => (string?)element.Attribute("Name"), element => element.Value);
        securityEvent.UserName = values["TargetUserName"].FirstOrDefault()
            ?? values["SubjectUserName"].FirstOrDefault();
        securityEvent.IpAddress = values["IpAddress"].FirstOrDefault()
            ?? values["SourceAddress"].FirstOrDefault();
    }

    private static string GetSeverityFromLevel(byte? level)
    {
        return level switch
        {
            1 => "Critical",
            2 => "Error",
            3 => "Warning",
            4 => "Information",
            _ => "Unknown"
        };
    }
}
