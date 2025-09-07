# xnetman-tk

Extended Network Manager (Tkinter version)

## To-Do

### Features

- [x] Add REFRESH button
- [x] Show current connected network
- [ ] Allow sorting by signal, name, freq, etc
- [ ] Allow connect to network

### UI/UX

- [x] Use bars instead of numbers for displaying signal
- [x] Allow open a independent window for most detailed view
- [ ] Color by type of security (Green for Open, Yellow for WPA, Red for WEP, etc)
- [ ] Light/Dark mode toggle
- [ ] Auto-refresh every X seconds (configurable)

### Additional information

- [ ] Show channel and frequency. For diagnosis (2,4GHz vs 5GHz)
- [ ] Router maker. Can be detected by MAC

### Diagnosis / Tools

- [ ] Speed test. Test latency and/or velocity
- [ ] Ping to gateway or DNS. To check if there is real connection

### Security

- [ ] Detect Duplicated Net (Evil Twin). Same SSID but different BSSID
- [ ] Verify weak encryption (WEP). Notify if you in danger
- [ ] Channel conesgtion analysis. Show most satured channels.
