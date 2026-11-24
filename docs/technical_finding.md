# Technical Finding: Detection of Outdated TKIP Encryption

## What was found

During a passive Wi-Fi security audit, WiFiWatch identified TKIP (Temporal Key Integrity Protocol) in 4 out of 5 audited access points.

The scan also detected WPS enabled on 3 access points.

## Why it matters

TKIP is an outdated encryption protocol originally introduced as a temporary improvement over WEP. It has known security weaknesses and is no longer recommended for modern wireless networks.

Modern networks should use WPA2 with AES-CCMP or WPA3 where supported.

WPS can also increase security risk, depending on its implementation and configuration.

## How WiFiWatch detected it

WiFiWatch passively inspected wireless beacon and related management information elements, including RSN security information.

It extracted advertised group and pairwise cipher suites and identified TKIP where present.

No packets were injected, no passwords were tested, and no active attacks were performed.

## Recommendation

For network administrators:

- Replace TKIP with AES-CCMP.
- Use WPA2 or WPA3 with strong authentication.
- Disable WPS if it is not required.
- Review wireless security settings regularly.

## Scope

This finding comes from a passive scan conducted in an authorized lab environment. Advertised security capabilities do not necessarily prove the exact configuration used by every connected client.
