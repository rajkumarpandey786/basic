package com.pandey.git.caller;
/**
 * 
 * @author Rajkumar Pandey
 *
 */
public class HelloGit {
public static void main(String[] args) {
	System.out.println("Pandey Says, Hello GIT HUB");
}
}
/**
 NET:06561001:NM COM [open] RQ from FRG
   NET:06561109:ELG: event detail [Switch state now [INACTIVE] ]
   NET:06561110:syslog: LOG_WARNING [Switch state now [INACTIVE] ]
   NET:06561110:Switch state now [INACTIVE] 
   NET:06562401:Message store is 0 percent used
   NET:06562401:SAF (ISS): no txns extracted from SAF
   NET:06562600:NM RQ[sign on] from FG
   NET:06562600:NETWORK [ABC] START PROCESS ACQ TXN
   NET:06562600:***********************************
   NET:06562600:Try to locate txn in Store
   NET:06562600:Looking up txn using SPA key
   NET:06562600:No match in disk log
   NET:06562600:Slot [1] allocated in store
   NET:06562600:GEN: ST  [newstore](0) EV  [nman](3) PR [net man rq](14) [RQ]
   NET:06562600:ACQ: msg class [   ]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 38 30 30                                      :004:: 0800
   NET:BUILD BM - UUUUUUBUUUBUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUbUUUUUUUUUUUUUUUUUUUUUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUb
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303065626]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 06 56 26                                   :005:: ___V&
   NET:----- Field 11 -----
   NET:F011 DATA PREP [673613]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:67 36 13                                         :003:: g6_
   NET:----- Field 13 -----
   NET:F013 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 48 -----
   NET:F048 DATA PREP (MIXED):
   NET:ISO: Completed part [1] of message
   NET:----- Field 70 -----
   NET:F070 DATA PREP [001]
   NET:ADD LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA ADDED
   NET:00 01                                            :002:: __
   NET:----- Field 128 -----
   NET:F128 DATA PREP [NNNNNNNN]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:ISO: Completed part [2] of message
   NET:06562600:ISO: Built primary bitmap with err [0]
   NET:06562600:ISO: Built secondary bitmap with err [0]
   NET:06562600:NKY: Net key (from STAN) [0673613030306562600000000000]
   NET:06562600:syslog: LOG_WARNING [Switch state now [W_SON] ]
   NET:06562600:Switch state now [W_SON] 
   NET:06562600:NETWORK [ABC] END PROCESS ACQ TXN
   NET:06562600:*********************************
   NET:06562638:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 38 31 30                                      :004:: 0810
   NET:DATA GOT [0810]
   NET:Msg type 810
   NET:06562638:ISO: RCV BM 
   NET:82 28 00 00 02 00 00 00                          :008:: _(______
   NET:06562638:ISO: RCV BM 
   NET:04 00 00 00 00 00 00 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 06 56 26                                   :005:: ___V&
   NET:F007 DATA GOT [0303065626]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:67 36 13                                         :003:: g6_
   NET:F011 DATA GOT [673613]
   NET:----- Field 13 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F013 DATA GOT [0303]
   NET:----- Field 39 -----
   NET:GET LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA RCVED
   NET:F0 F0                                            :002:: __
   NET:F039 DATA GOT [00]
   NET:ISO: Skipping F065 - it's a bitmap
   NET:----- Field 70 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:00 01                                            :002:: __
   NET:F070 DATA GOT [001]
   NET:----- Field 128 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:F128 DATA GOT [NNNNNNNN]
   NET:06562638:NKY: Net key (from STAN) [0673613030306562600000000000]
   NET:06562638:TC [3] NET MSGT [810] SPA MSGT [999]
   NET:06562638:NET: net_process_mac, ACQ, RSP, KEK USER [ABC]
   NET:06562638:NET: MAC Process: Return [0]
   NET:06562638:NETWORK [ABC] START PROCESS ACQ TXN
   NET:06562638:***********************************
   NET:06562638:Try to locate txn in Store
   NET:06562638:Request located in STORE slot [1]
   NET:06562638:GEN: ST  [wfrsp](2) EV  [nman](3) PR [net man rsp](15) [RSP]
   NET:F001 expctd [U] rcvd [P] sdst [S]
   NET:F007 expctd [M] rcvd [P] sdst [S]
   NET:COMP Src [0303065626] Dst [0303065626]
   NET:F011 expctd [M] rcvd [P] sdst [L]
   NET:COMP Src [673613] Dst [673613]
   NET:F013 expctd [M] rcvd [P] sdst [S]
   NET:COMP Src [0303] Dst [0303]
   NET:F039 expctd [R] rcvd [P] sdst [S]
   NET:F070 expctd [M] rcvd [P] sdst [H]
   NET:COMP Src [1] Dst [1]
   NET:F128 expctd [O] rcvd [P] sdst [S]
   NET:COPY Src [NNNNNNNN] Dst []
   NET:06562638:ACQ: Authorised response to sign on received.
   NET:06562638:ACQ: Now waiting for key exchange
   NET:06562638:syslog: LOG_WARNING [Switch state now [KYS_OUT] ]
   NET:06562638:Switch state now [KYS_OUT] 
   NET:06562638:NETWORK [ABC] END PROCESS ACQ TXN
   NET:06562638:*********************************
   NET:06563903:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 38 30 30                                      :004:: 0800
   NET:DATA GOT [0800]
   NET:Msg type 800
   NET:06563903:ISO: RCV BM 
   NET:82 28 00 00 00 01 00 00                          :008:: _(______
   NET:06563903:ISO: RCV BM 
   NET:04 00 00 00 00 00 00 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 06 56 26                                   :005:: ___V&
   NET:F007 DATA GOT [0303065626]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:77 30 54                                         :003:: w0T
   NET:F011 DATA GOT [773054]
   NET:----- Field 13 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F013 DATA GOT [0303]
   NET:----- Field 48 -----
   NET:GET LEN: len fmt [5] len len [2] len [44] err [0]
   NET:DATA RCVED
   NET:00 44 2A 2A 2A 2A 2A 2A  2A 2A 2A 2A 2A 2A 2A 2A :010:: _D**************
   NET:2A 2A 2A 2A 2A 2A 2A 2A  2A 2A 2A 2A 2A 2A 2A 2A :020:: ****************
   NET:2A 2A 2A 2A 2A 2A 2A 2A  2A 2A 2A 2A 2A 2A       :02E:: **************
   NET:F048 DATA GOT (MIXED):
   NET:2A 2A 2A 2A 2A 2A 2A 2A  2A 2A 2A 2A 2A 2A 2A 2A :010:: ****************
   NET:2A 2A 2A 2A 2A 2A 2A 2A  2A 2A 2A 2A 2A 2A 2A 2A :020:: ****************
   NET:2A 2A 2A 2A 2A 2A 2A 2A  2A 2A 2A 2A             :02C:: ************
   NET:ISO: Skipping F065 - it's a bitmap
   NET:----- Field 70 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:08 11                                            :002:: __
   NET:F070 DATA GOT [811]
   NET:----- Field 128 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:F128 DATA GOT [NNNNNNNN]
   NET:06563903:NKY: Net key (from STAN) [0773054030306562600000000000]
   NET:06563904:TC [3] NET MSGT [800] SPA MSGT [999]
   NET:06563904:NET: net_process_mac, ISS, RQ, KEK USER [ABC]
   NET:06563904:NET: MAC Process: Return [0]
   NET:06563904:NETWORK [ABC] START PROCESS ISS TXN
   NET:06563904:***********************************
   NET:06563904:New calendar day [030326] detected. Performing new day processing.
   NET:06563904:Try to locate txn in Store
   NET:06563904:Looking up txn using NET key
   NET:06563904:No match in disk log
   NET:06563904:Slot [1] allocated in store
   NET:06563904:GEN: ST  [newstore](0) EV  [nman](3) PR [net man rq](14) [RQ]
   NET:06563905:Key acceptance received. KEK user [ABC]
   NET:06563905:ENC: Sending REQ - My PID [662221] Msg Seqno [35472] Rsp MSQID [301993078]
   NET:06563907:ENC: Received RS - RQ PID [662221] Msg Seqno [35472] Rsp MSQID [301993078]
   NET:06563907:ABC WK New keycheck
   NET:39 44 37 30 42 30 30 30  30 30 30 30 30 30 30 30 :010:: 9D70B00000000000
   NET:06563907:ENC: Sending REQ - My PID [662221] Msg Seqno [35473] Rsp MSQID [301993078]
   NET:06563909:ENC: Received RS - RQ PID [662221] Msg Seqno [35473] Rsp MSQID [301993078]
   NET:06563909:ABC WK New keycheck
   NET:31 39 43 45 32 43 30 30  30 30 30 30 30 30 30 30 :010:: 19CE2C0000000000
   NET:06563909:ISS: Key update processed OK
   NET:06563909:ELG: event detail [Switch state now [ACTIVE] ]
   NET:06563909:syslog: LOG_WARNING [Switch state now [ACTIVE] ]
   NET:06563909:Switch state now [ACTIVE] 
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 38 31 30                                      :004:: 0810
   NET:BUILD BM - BUUUUUCUUUCUCUUUUUUUUUUUUUUUUUUTUUUUUUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUb
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303065626]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 06 56 26                                   :005:: ___V&
   NET:----- Field 11 -----
   NET:F011 DATA PREP [773054]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:77 30 54                                         :003:: w0T
   NET:----- Field 13 -----
   NET:F013 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 32 -----
   NET:F032 DATA PREP []
   NET:----- Field 39 -----
   NET:F039 DATA PREP [00]
   NET:ADD LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA ADDED
   NET:F0 F0                                            :002:: __
   NET:ISO: Completed part [1] of message
   NET:----- Field 70 -----
   NET:F070 DATA PREP [811]
   NET:ADD LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA ADDED
   NET:08 11                                            :002:: __
   NET:----- Field 128 -----
   NET:F128 DATA PREP [NNNNNNNN]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:ISO: Completed part [2] of message
   NET:06563909:ISO: Built primary bitmap with err [0]
   NET:06563909:ISO: Built secondary bitmap with err [0]
   NET:06563909:NKY: Net key (from STAN) [0773054030306562600000000000]
   NET:06563909:NETWORK [ABC] END PROCESS ISS TXN
   NET:06563909:***********************************
   NET:06563909:Message store is 0 percent used
   NET:06563910:SAF (ACQ): no txns extracted from SAF
   NET:06574001:NM RQ[echo_test] from FG
   NET:06574001:NETWORK [ABC] START PROCESS ACQ TXN
   NET:06574001:***********************************
   NET:06574001:Try to locate txn in Store
   NET:06574001:Looking up txn using SPA key
   NET:06574001:No match in disk log
   NET:06574001:Slot [1] allocated in store
   NET:06574001:GEN: ST  [newstore](0) EV  [nman](3) PR [net man rq](14) [RQ]
   NET:06574001:ACQ: msg class [   ]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 38 30 30                                      :004:: 0800
   NET:BUILD BM - UUUUUUBUUUBUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUbUUUUUUUUUUUUUUUUUUUUUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUb
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303065740]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 06 57 40                                   :005:: ___W@
   NET:----- Field 11 -----
   NET:F011 DATA PREP [673614]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:67 36 14                                         :003:: g6_
   NET:----- Field 13 -----
   NET:F013 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 48 -----
   NET:F048 DATA PREP (MIXED):
   NET:ISO: Completed part [1] of message
   NET:----- Field 70 -----
   NET:F070 DATA PREP [301]
   NET:ADD LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA ADDED
   NET:03 01                                            :002:: __
   NET:----- Field 128 -----
   NET:F128 DATA PREP [NNNNNNNN]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:ISO: Completed part [2] of message
   NET:06574001:ISO: Built primary bitmap with err [0]
   NET:06574001:ISO: Built secondary bitmap with err [0]
   NET:06574001:NKY: Net key (from STAN) [0673614030306574000000000000]
   NET:06574001:MAC: Generating MAC
   NET:06574001:ENC: Sending REQ - My PID [662221] Msg Seqno [35474] Rsp MSQID [301993078]
   NET:06574001:OUTBOUND message will be sent once MAC is generated
   NET:06574001:NETWORK [ABC] END PROCESS ACQ TXN
   NET:06574001:*********************************
   NET:06574005:ENC: Prefetch RS - RQ PID [662221] Msg Seqno [35474] Rsp MSQID [301993078]
   NET:06574005:MAC: Retrieving completed MAC from ENC
   NET:06574005:Extracted OUTBOUND message from MAC Cache for sending
   NET:06574039:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 38 31 30                                      :004:: 0810
   NET:DATA GOT [0810]
   NET:Msg type 810
   NET:06574039:ISO: RCV BM 
   NET:82 28 00 00 02 00 00 00                          :008:: _(______
   NET:06574039:ISO: RCV BM 
   NET:04 00 00 00 00 00 00 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 06 57 40                                   :005:: ___W@
   NET:F007 DATA GOT [0303065740]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:67 36 14                                         :003:: g6_
   NET:F011 DATA GOT [673614]
   NET:----- Field 13 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F013 DATA GOT [0303]
   NET:----- Field 39 -----
   NET:GET LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA RCVED
   NET:F0 F0                                            :002:: __
   NET:F039 DATA GOT [00]
   NET:ISO: Skipping F065 - it's a bitmap
   NET:----- Field 70 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:03 01                                            :002:: __
   NET:F070 DATA GOT [301]
   NET:----- Field 128 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:37 32 30 31 36 32 38 42                          :008:: 7201628B
   NET:F128 DATA GOT [7201628B]
   NET:06574039:NKY: Net key (from STAN) [0673614030306574000000000000]
   NET:06574039:TC [3] NET MSGT [810] SPA MSGT [999]
   NET:06574039:NET: net_process_mac, ACQ, RSP, KEK USER [ABC]
   NET:06574039:NET: Calculate MAC field [ACQ] [RSP] - INCOMING
   NET:06574039:NET: Validating MAC
   NET:06574039:ENC: Sending REQ - My PID [662221] Msg Seqno [35475] Rsp MSQID [301993078]
   NET:06574041:ENC: Received RS - RQ PID [662221] Msg Seqno [35475] Rsp MSQID [301993078]
   NET:06574041:NET: ENC ERR: MAC is bad 
   NET:06574041:NET: MAC Verify FAIL: DATA[7201628B] MAC[7201628B]
   NET:06574041:NET: MAC Process: Return [25]
   NET:06582500:Message store is 0 percent used
   NET:06582500:SAF (ISS): no txns extracted from SAF
   NET:06582600:Timeout at SLOT [1] - time in [1772510260] now [1772510306] tout [45]
   NET:06582600:GEN: ST  [tout](3) EV  [nman](3) PR [net man rq timeout](13) [RQ]
   NET:06582600:======== SDS DUMP FROM p_net_man_tout =========================
   NET:CONTROL: state [3] tc [3] [RQ] bday [8558] nday [829] cache slot [1]
   NET:LOHDR  : id [9999] seq [1773] imd [777777] date [260303] time [065740]
   NET:BASEDATA: amt [0000000] device [
   NET:NETDATA: xmit_date_time [0303065740] RRN [] 
   NET:NETKEY : [0673614030306574000000000000] 
   NET:06584000:Message store is 0 percent used
   NET:06584000:SAF (ACQ): no txns extracted from SAF
   NET:06584100:NM RQ[echo_test] from FG
   NET:06584100:NETWORK [ABC] START PROCESS ACQ TXN
   NET:06584100:***********************************
   NET:06584100:Try to locate txn in Store
   NET:06584100:Looking up txn using SPA key
   NET:06584100:No match in disk log
   NET:06584100:Slot [1] allocated in store
   NET:06584100:GEN: ST  [newstore](0) EV  [nman](3) PR [net man rq](14) [RQ]
   NET:06584100:ACQ: msg class [   ]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 38 30 30                                      :004:: 0800
   NET:BUILD BM - UUUUUUBUUUBUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUbUUUUUUUUUUUUUUUUUUUUUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUb
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303065841]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 06 58 41                                   :005:: ___XA
   NET:----- Field 11 -----
   NET:F011 DATA PREP [673615]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:67 36 15                                         :003:: g6_
   NET:----- Field 13 -----
   NET:F013 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 48 -----
   NET:F048 DATA PREP (MIXED):
   NET:ISO: Completed part [1] of message
   NET:----- Field 70 -----
   NET:F070 DATA PREP [301]
   NET:ADD LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA ADDED
   NET:03 01                                            :002:: __
   NET:----- Field 128 -----
   NET:F128 DATA PREP [NNNNNNNN]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:ISO: Completed part [2] of message
   NET:06584100:ISO: Built primary bitmap with err [0]
   NET:06584100:ISO: Built secondary bitmap with err [0]
   NET:06584100:NKY: Net key (from STAN) [0673615030306584100000000000]
   NET:06584100:MAC: Generating MAC
   NET:06584100:ENC: Sending REQ - My PID [662221] Msg Seqno [35476] Rsp MSQID [301993078]
   NET:06584100:OUTBOUND message will be sent once MAC is generated
   NET:06584100:NETWORK [ABC] END PROCESS ACQ TXN
   NET:06584100:*********************************
   NET:06584104:ENC: Prefetch RS - RQ PID [662221] Msg Seqno [35476] Rsp MSQID [301993078]
   NET:06584104:MAC: Retrieving completed MAC from ENC
   NET:06584104:Extracted OUTBOUND message from MAC Cache for sending
   NET:06584138:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 38 31 30                                      :004:: 0810
   NET:DATA GOT [0810]
   NET:Msg type 810
   NET:06584138:ISO: RCV BM 
   NET:82 28 00 00 02 00 00 00                          :008:: _(______
   NET:06584138:ISO: RCV BM 
   NET:04 00 00 00 00 00 00 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 06 58 41                                   :005:: ___XA
   NET:F007 DATA GOT [0303065841]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:67 36 15                                         :003:: g6_
   NET:F011 DATA GOT [673615]
   NET:----- Field 13 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F013 DATA GOT [0303]
   NET:----- Field 39 -----
   NET:GET LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA RCVED
   NET:F0 F0                                            :002:: __
   NET:F039 DATA GOT [00]
   NET:ISO: Skipping F065 - it's a bitmap
   NET:----- Field 70 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:03 01                                            :002:: __
   NET:F070 DATA GOT [301]
   NET:----- Field 128 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:34 46 43 46 41 39 45 45                          :008:: 4FCFA9EE
   NET:F128 DATA GOT [4FCFA9EE]
   NET:06584138:NKY: Net key (from STAN) [0673615030306584100000000000]
   NET:06584138:TC [3] NET MSGT [810] SPA MSGT [999]
   NET:06584138:NET: net_process_mac, ACQ, RSP, KEK USER [ABC]
   NET:06584138:NET: Calculate MAC field [ACQ] [RSP] - INCOMING
   NET:06584138:NET: Validating MAC
   NET:06584138:ENC: Sending REQ - My PID [662221] Msg Seqno [35477] Rsp MSQID [301993078]
   NET:06584141:ENC: Received RS - RQ PID [662221] Msg Seqno [35477] Rsp MSQID [301993078]
   NET:06584141:NET: ENC ERR: MAC is bad 
   NET:06584141:NET: MAC Verify FAIL: DATA[4FCFA9EE] MAC[4FCFA9EE]
   NET:06584141:NET: MAC Process: Return [25]
   NET:06592700:Timeout at SLOT [1] - time in [1772510321] now [1772510367] tout [45]
   NET:06592700:GEN: ST  [tout](3) EV  [nman](3) PR [net man rq timeout](13) [RQ]
   NET:06592700:======== SDS DUMP FROM p_net_man_tout =========================
   NET:CONTROL: state [3] tc [3] [RQ] bday [8558] nday [829] cache slot [1]
   NET:LOHDR  : id [9999] seq [1773] imd [777777] date [260303] time [065841]
   NET:BASEDATA: amt [0000000] device [
   NET:NETDATA: xmit_date_time [0303065841] RRN [] 
   NET:NETKEY : [0673615030306584100000000000] 
   NET:06594200:NM RQ[echo_test] from FG
   NET:06594200:NETWORK [ABC] START PROCESS ACQ TXN
   NET:06594200:***********************************
*/
