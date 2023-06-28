### wsjt2fdlog
A very basic script that forwards WSJT-X "QSO Logged" packets to FDLog (https://www.fdlog.us)

### Usage
        usage: wsjt2fdlog [-h] [--wsjt-port WSJT_PORT] [--fdlog-host FDLOG_HOST]
                          [--fdlog-port FDLOG_PORT] [--authkey AUTHKEY]
                          [--contest CONTEST] [--host HOST] [--op OP]
                          [--logger LOGGER]
        
        Forward WSJT-X QSO Logged Packets to FDLog
        
        options:
          -h, --help            show this help message and exit
          --wsjt-port WSJT_PORT
                                WSJT-X UDP Port (default 2237)
          --fdlog-host FDLOG_HOST
                                FDLog Hostname/IP (default 127.0.0.1)
          --fdlog-port FDLOG_PORT
                                FDLog UDP Port (default 7373)
          --authkey AUTHKEY     FDLog authkey (default 'tst')
          --contest CONTEST     Contest Identifier (default 'fd')
          --host HOST           FDLog QSO Host (default 'JCB-PBP')
          --op OP               FDLog QSO Operator (default 'jcb')
          --logger LOGGER       FDLog QSO Logger (default 'jcb')