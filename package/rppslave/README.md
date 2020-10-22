# Rppslave
rppslave is RPP(Revanche Provisioning Protocol) slave entity running in IPQ system.

# Design

## Monitor thread
```
  This thread monitor associate state of all active stations in each radio every 1 second, 
  when associate state change it will send notify message to wlanmgrd.

  In order to get station state by using iwpriv and iwconfig command that will spawn a 
  new process, the wpa_supplicant provide a control interface that can be by external program
  to get station state and bssid.
```

### wpa control interface
```
  wpa_supplicant provide a control interface that can be used by external program to control 
  the operations of the wpa_supplicant daemon and to get status information.

  In the current design, message parser thread and monitor thread use separate wpa control 
  interface object (per radio) for avoid using mutex to prevent data race with each other.
  In the future if another thread (like statistics thread) want to use the exists wpa control 
  interface object, the mutex can be add.

  To get the station state, use function wpa_ctrl_request() with command STATUS and then
  parse wpa_state and bssid (exists when station associated with AP) from reply message.

  To configure network interface, use function wpa_ctrl_request() with various command
  and parameters (Example: INTERFACE_ADD, SET_NETWORK) and then check the command request
  status from reply message.
  
  More information about wpa control interface command structure is in wpa_cli.c file.
```
