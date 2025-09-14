# xnetman-tk

Extended Network Manager (Tkinter version)

## To-Do

### Features

- [x] Add REFRESH button
- [x] Show current connected network
- [x] Show saved connections
- [ ] Allow sorting by signal, name, freq, etc
- [ ] Allow to connect to network
- [ ] Allow viewing password of saved networks
- [ ] Allow deleting saved networks
- [ ] Allow sharing network via QR code

### UI/UX

- [x] Use bars instead of numbers for displaying signal
- [x] Open an independent window for most detailed view of network
- [ ] Color by type of security (Green for Open, Yellow for WPA, Red for WEP, etc.)
- [ ] Light/Dark mode toggle
- [ ] Auto-refresh every 5 seconds

### Additional information

- [ ] Show channel and frequency. For diagnosis (2,4GHz vs 5GHz)
- [x] Router maker. Can be detected by MAC

### Diagnosis / Tools

- [ ] Speed test. Test latency and/or velocity
- [ ] Ping to gateway or DNS. To check if there is real connection

### Security

- [ ] Detect Duplicated Net (Evil Twin). Same SSID but different BSSID
- [ ] Verify weak encryption (WEP). Notify if you in danger
- [ ] Channel congestion analysis. Show most saturated channels.
