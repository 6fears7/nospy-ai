# Known limitations

[Back to the README](../README.md)

| Limitation | Detail |
|---|---|
| Changed values | Base64, split or re-cased values, and values under 4 characters, are not recognized in the response |
| Remembered values | Memory storage only. |
| Scope | Traffic that goes through the base URL. Other telemetry is not intercepted |
| Detection | Regex only. Personal names are not detected. Postal addresses only in the listed formats |
| Placeholders | Despite precaution, there is a risk a model may change or refuse a placeholder |
| Threat model | Protects against provider storage, training and leaks. Does not protect against a provider attacking through the agent |
| Anonymity | The provider still sees anything undetected, the tool list, timing, sizes, your source IP and your account |
