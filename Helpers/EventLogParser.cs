using System;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Helpers;

public static class EventLogParser
{
    public static SecurityEvent Parse(EventRecord eventRecord, string logName)
    {
        var securityEvent = new SecurityEvent
        {
            EventId = eventRecord.Id,
            Timestamp = eventRecord.TimeCreated ?? DateTime.UtcNow,
            LogName = logName,
            Source = eventRecord.ProviderName ?? "Unknown",
            Description = eventRecord.FormatDescription() ?? $"Event ID {eventRecord.Id}",
            Severity = GetSeverityFromLevel(eventRecord.Level)
        };

        // Extract additional data from event properties
        try
        {
            if (eventRecord.Properties != null && eventRecord.Properties.Count > 0)
            {
                // For security events, try to extract username (typically in property 5 or 1)
                if (logName == "Security" && eventRecord.Properties.Count > 5)
                {
                    securityEvent.UserName = eventRecord.Properties[5]?.Value?.ToString();
                }

                // For login events, try to extract IP address (typically in property 18 or 19)
                if ((eventRecord.Id == 4624 || eventRecord.Id == 4625) &&
                    eventRecord.Properties.Count > 18)
                {
                    securityEvent.IpAddress = eventRecord.Properties[18]?.Value?.ToString();
                }
            }
        }
        catch
        {
            // If property extraction fails, continue without it
        }

        return securityEvent;
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
