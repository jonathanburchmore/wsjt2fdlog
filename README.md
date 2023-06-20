### wsjt2fdlog
A very basic script that forwards WSJT-X "QSO Logged" packets to FDLog (https://www.fdlog.us)

### Customizing
Currently, all values are hard coded.  You will almost certainly want to change:

1. Message source (currently "JCB-PBP")
2. Operator and Logger (currently "jcb")
3. FDLog authorization key (currently "tst")
4. FDLog UDP forwarding destination (currently 127.0.0.1)

### Usage
1. Start WSJT-X
2. Start FDLog
3. Run wsjt2fdlog

The script will automatically pick up WSJT-X UDP messages, reformat them and forward them to FDLog.
