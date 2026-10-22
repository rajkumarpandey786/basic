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


   NET:07125500:NETWORK [ABC] START PROCESS ACQ TXN
   NET:07125500:***********************************
   NET:07125500:Try to locate txn in Store
   NET:07125500:Looking up txn using SPA key
   NET:07125500:No match in disk log
   NET:07125500:Slot [1] allocated in store
   NET:07125500:GEN: ST  [newstore](0) EV  [nman](3) PR [net man rq](14) [RQ]
   NET:07125500:ACQ: msg class [   ]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 38 30 30                                      :004:: 0800
   NET:BUILD BM - UUUUUUBUUUBUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUbUUUUUUUUUUUUUUUUUUUUUCUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUb
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303071255]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 07 12 55                                   :005:: ____U
   NET:----- Field 11 -----
   NET:F011 DATA PREP [673629]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:67 36 29                                         :003:: g6)
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
   NET:07125500:ISO: Built primary bitmap with err [0]
   NET:07125500:ISO: Built secondary bitmap with err [0]
   NET:07125500:NKY: Net key (from STAN) [0673629030307125500000000000]
   NET:07125500:MAC: Generating MAC
   NET:07125500:ENC: Sending REQ - My PID [662221] Msg Seqno [35504] Rsp MSQID [301993078]
   NET:07125500:OUTBOUND message will be sent once MAC is generated
   NET:07125500:NETWORK [ABC] END PROCESS ACQ TXN
   NET:07125500:*********************************
   NET:07125504:ENC: Prefetch RS - RQ PID [662221] Msg Seqno [35504] Rsp MSQID [301993078]
   NET:07125504:MAC: Retrieving completed MAC from ENC
   NET:07125504:Extracted OUTBOUND message from MAC Cache for sending
   NET:07125536:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 38 31 30                                      :004:: 0810
   NET:DATA GOT [0810]
   NET:Msg type 810
   NET:07125536:ISO: RCV BM 
   NET:82 28 00 00 02 00 00 00                          :008:: _(______
   NET:07125536:ISO: RCV BM 
   NET:04 00 00 00 00 00 00 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 07 12 55                                   :005:: ____U
   NET:F007 DATA GOT [0303071255]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:67 36 29                                         :003:: g6)
   NET:F011 DATA GOT [673629]
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
   NET:33 41 44 43 37 38 34 32                          :008:: 3ADC7842
   NET:F128 DATA GOT [3ADC7842]
   NET:07125537:NKY: Net key (from STAN) [0673629030307125500000000000]
   NET:07125537:TC [3] NET MSGT [810] SPA MSGT [999]
   NET:07125537:NET: net_process_mac, ACQ, RSP, KEK USER [ABC]
   NET:07125537:NET: Calculate MAC field [ACQ] [RSP] - INCOMING
   NET:07125537:NET: Validating MAC
   NET:07125537:ENC: Sending REQ - My PID [662221] Msg Seqno [35505] Rsp MSQID [301993078]
   NET:07125539:ENC: Received RS - RQ PID [662221] Msg Seqno [35505] Rsp MSQID [301993078]
   NET:07125539:NET: ENC ERR: MAC is bad 
   NET:07125539:NET: MAC Verify FAIL: DATA[3ADC7842] MAC[3ADC7842]
   NET:07125539:NET: MAC Process: Return [25]
   NET:07134102:Timeout at SLOT [1] - time in [1772511175] now [1772511221] tout [45]
   NET:07134102:GEN: ST  [tout](3) EV  [nman](3) PR [net man rq timeout](13) [RQ]
   NET:07134102:======== SDS DUMP FROM p_net_man_tout =========================
   NET:CONTROL: state [3] tc [3] [RQ] bday [8558] nday [829] cache slot [1]
   NET:LOHDR  : id [9999] seq [1775] imd [777777] date [260303] time [071255]
   NET:BASEDATA: amt [0000000] device [
   NET:NETDATA: xmit_date_time [0303071255] RRN [] 
   NET:NETKEY : [0673629030307125500000000000] 
   NET:07134565:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 32 30 30                                      :004:: 0200
   NET:DATA GOT [0200]
   NET:Msg type 200
   NET:07134565:ISO: RCV BM 
   NET:F2 3B 46 81 08 E0 80 00                          :008:: _;F_____
   NET:07134565:ISO: RCV BM 
   NET:00 00 00 00 02 00 01 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 2 -----
   NET:GET LEN: len fmt [1] len len [1] len [16] err [0]
   NET:DATA RCVED
   NET:16 2A 2A 2A 2A 2A 2A 2A  2A                      :009:: _********
   NET:F002 DATA GOT [787878******0000]
   NET:----- Field 3 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:37 00 00                                         :003:: 7__
   NET:F003 DATA GOT [370000]
   NET:----- Field 4 -----
   NET:GET LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA RCVED
   NET:00 00 00 00 00 00                                :006:: ______
   NET:F004 DATA GOT [000000000000]
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 07 13 40                                   :005:: ____@
   NET:F007 DATA GOT [0303071340]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:60 18 94                                         :003:: `__
   NET:F011 DATA GOT [601894]
   NET:----- Field 12 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:07 13 40                                         :003:: __@
   NET:F012 DATA GOT [071340]
   NET:----- Field 13 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F013 DATA GOT [0303]
   NET:----- Field 15 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F015 DATA GOT [0303]
   NET:----- Field 16 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F016 DATA GOT [0303]
   NET:----- Field 18 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:59 99                                            :002:: Y_
   NET:F018 DATA GOT [5999]
   NET:----- Field 22 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:00 11                                            :002:: __
   NET:F022 DATA GOT [011]
   NET:----- Field 23 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:00 00                                            :002:: __
   NET:F023 DATA GOT [000]
   NET:----- Field 25 -----
   NET:GET LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA RCVED
   NET:05                                               :001:: _
   NET:F025 DATA GOT [05]
   NET:----- Field 32 -----
   NET:GET LEN: len fmt [1] len len [1] len [6] err [0]
   NET:DATA RCVED
   NET:06 62 79 23                                      :004:: _by#
   NET:F032 DATA GOT [627923]
   NET:----- Field 37 -----
   NET:GET LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA RCVED
   NET:F7 F1 F6 F5 F4 F2 F4 F6  F4 F4 F9 F1             :00C:: ____________
   NET:F037 DATA GOT [716542464491]
   NET:----- Field 41 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:F9 F3 F6 F4 F9 F4 F7 F0                          :008:: ________
   NET:F041 DATA GOT [93649470]
   NET:----- Field 42 -----
   NET:GET LEN: len fmt [0] len len [0] len [15] err [0]
   NET:DATA RCVED
   NET:F1 F0 F8 F4 F6 F4 40 40  40 40 40 40 40 40 40    :00F:: ______@@@@@@@@@
   NET:F042 DATA GOT [108464         ]
   NET:----- Field 43 -----
   NET:GET LEN: len fmt [0] len len [0] len [40] err [0]
   NET:DATA RCVED
   NET:D7 C5 C7 C1 E2 E4 E2 40  40 40 40 40 40 40 40 40 :010:: _______@@@@@@@@@
   NET:40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40 :020:: @@@@@@@@@@@@@@@@
   NET:40 40 40 40 E2 E3 E4 C7                          :028:: @@@@____
   NET:F043 DATA GOT [PEGASUS                             STUG]
   NET:----- Field 49 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:08 00                                            :002:: __
   NET:F049 DATA GOT [800]
   NET:ISO: Skipping F065 - it's a bitmap
   NET:----- Field 103 -----
   NET:GET LEN: len fmt [1] len len [1] len [13] err [0]
   NET:DATA RCVED
   NET:13 F0 F1 F0 F0 F8 F1 F9  F8 F0 F5 F2 F0 F0       :00E:: ______________
   NET:F103 DATA GOT [0100819805200]
   NET:----- Field 120 -----
   NET:GET LEN: len fmt [5] len len [2] len [4] err [0]
   NET:DATA RCVED
   NET:00 04 C4 D7 D6 E2                                :006:: ______
   NET:F120 DATA GOT [DPOS]
   NET:----- Field 128 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:F128 DATA GOT [NNNNNNNN]
   NET:07134565:NKY: Net key (from STAN) [1601894030307134000000627923]
   NET:07134565:TC [80] NET MSGT [200] SPA MSGT [602]
   NET:07134565:NET: net_process_mac, ISS, RQ, KEK USER [ABC]
   NET:07134565:NET: MAC Process: Return [0]
   NET:07134565:NETWORK [ABC] START PROCESS ISS TXN
   NET:07134565:***********************************
   NET:07134565:Try to locate txn in Store
   NET:07134565:Looking up txn using NET key
   NET:07134566:No match in disk log
   NET:07134566:Slot [1] allocated in store
   NET:07134566:GEN: ST  [newstore](0) EV  [NamQ](80) PR [txn rq](1) [RQ]
   NET:07134566:Expected rq bm [RRDROORUUURRDOOOURUUUDOURUUUUUUDOUdURUUURRRUUUUUROOdUUdUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUdOUUOOOUUOUUUUUUUURUUUUUUUR]
   NET:F001 expctd [R] rcvd [P] 
   NET:F002 expctd [R] rcvd [P] 
   NET:F003 expctd [D] rcvd [P] 
   NET:F004 expctd [R] rcvd [P] 
   NET:F005 expctd [O] rcvd [U] 
   NET:F006 expctd [O] rcvd [U] 
   NET:F007 expctd [R] rcvd [P] 
   NET:F011 expctd [R] rcvd [P] 
   NET:F012 expctd [R] rcvd [P] 
   NET:F013 expctd [D] rcvd [P] 
   NET:F014 expctd [O] rcvd [U] 
   NET:F015 expctd [O] rcvd [P] 
   NET:F016 expctd [O] rcvd [P] 
   NET:F018 expctd [R] rcvd [P] 
   NET:F022 expctd [D] rcvd [P] 
   NET:POS Entry Mode (Network format): [011]
   NET:POS Entry Mode (Sparrow format): [011]
   NET:F023 expctd [O] rcvd [P] 
   NET:F025 expctd [R] rcvd [P] 
   NET:F032 expctd [D] rcvd [P] 
   NET:F033 expctd [O] rcvd [U] 
   NET:F035 expctd [d] rcvd [U] 
   NET:F037 expctd [R] rcvd [P] 
   NET:F041 expctd [R] rcvd [P] 
   NET:F042 expctd [R] rcvd [P] 
   NET:F043 expctd [R] rcvd [P] 
   NET:F049 expctd [R] rcvd [P] 
   NET:F050 expctd [O] rcvd [U] 
   NET:F051 expctd [O] rcvd [U] 
   NET:F052 expctd [d] rcvd [U] 
   NET:F055 expctd [d] rcvd [U] 
   NET:F102 expctd [d] rcvd [U] 
   NET:F103 expctd [O] rcvd [P] 
   NET:F106 expctd [O] rcvd [U] 
   NET:F107 expctd [O] rcvd [U] 
   NET:F108 expctd [O] rcvd [U] 
   NET:F111 expctd [O] rcvd [U] 
   NET:F120 expctd [R] rcvd [P] 
   NET:F128 expctd [R] rcvd [P] 
   NET:07134566:ISS: Build variable data type [X] for msg type [200]
   NET:07134566:ISS: build_type_netx 112v3
   NET:07134566:No expiry date supplied - zero-filling T2
   NET:07134566:ISS: Performing licenced issuer IMD 787878 check
   NET:07134566:TLVX: Added 59 byte TLVX Data Block - Var Data Type [x]
   NET:07134566:ISS: REQ TO HOST LO_MSG: 
   NET:07134566:IMD:627923 800 0000 Id:9999 Seq:1863
   NET:07134566:Fun:(602) On/Off:[Auth(&Post)] Date:260303 Time:071340
   NET:602 Network Request X Type (net_ext_type v1.12.3)
   NET:Variable data type      [x]
   NET:Index                   [01]
   NET:Track 2                 [787878******0000*****                ]
   NET:Txn (dispense) amount   [000000000000000]
   NET:Txn (dispense) curr code[800]
   NET:ISO TA (account type)   [0]
   NET:PIN block format        [00]
   NET:PIN block               [XXXXXXXXXXXXXXXX]
   NET:Acquiring device        [P]
   NET:Network code            [W]
   NET:Language code           [1]
   NET:Action for PIN block    [I] (Ignore)
   NET:Transaction status      [r] (Request)
   NET:Action code             [0] (return card)
   NET:Response code           [00] (Authorised)
   NET:------------------------
   NET:NET extension version   [03]
   NET:External network ID     [ABC]
   NET:Authorisation code      [491863]
   NET:Acq institution ID      [627923     ]
   NET:Forwarding inst ID      [           ]
   NET:Merchant category code  [5999]
   NET:Card acceptor term ID   [93649470        ]
   NET:Card acceptor ID        [108464         ]
   NET:Card acceptor name/loc  [PEGASUS                             STUG]
   NET:Currency code billing   [000]
   NET:Transaction amount bill [+00000000000000]
   NET:Conversion rate billing [61000000]
   NET:Cashback amount billing [+00000000000000]
   NET:Cashback amount device  [+00000000000000]
   NET:Cashback amnt src acct  [+00000000000000]
   NET:Settlement currency     [000]
   NET:Settlement amount       [+00000000000000]
   NET:Conversion rate settl   [61000000]
   NET:Actual balance          [+00000000000000]
   NET:Available balance       [+00000000000000]
   NET:Retrieval reference no  [716542464491]
   NET:Systems trace audit no  [601894]
   NET:Transaction ID          [000000000000000]
   NET:TLVX Data Block is present - size [59] bytes.  Field Data:
   NET:TLVX Field [NETPOSEM]
   NET:30 31 31 00                                      :004:: 011_
   NET:TLVX Field [ACC1SRC]
   NET:48                                               :001:: H
   NET:TLVX Field [ACC1NO]
   NET:30 31 30 30 38 31 39 38  30 35 32 30 30 00       :00E:: 0100819805200_
   NET:TLVX Field [CHCODE]
   NET:44 50 4F 53 00                                   :005:: DPOS_
   NET:TLVX Data Block contains 4 fields
   NET:07134566:NETWORK [ABC] END PROCESS ISS TXN
   NET:07134566:***********************************
   NET:07134584:Read IMT_LOMSG
   NET:07134584:SPA RCV: 
   NET:07134584:IMD:627923 800 0000 Id:9999 Seq:1863
   NET:07134584:Fun:(602) On/Off:[Auth(&Post)] Date:260303 Time:071340
   NET:602 Network Auth Response A Type (na_type)
   NET:Variable data type      [a]
   NET:Index                   [00]
   NET:Track 2                 [787878*********0000                  ]
   NET:Txn (dispense) amount   [+00000000000000]
   NET:Txn (dispense) curr code[800]
   NET:ISO TA (account type)   [1]
   NET:PIN block format        [00]
   NET:PIN block               [XXXXXXXXXXXXXXXX]
   NET:Acquiring device        [P]
   NET:Network code            [W]
   NET:Language code           [0]
   NET:Action for PIN block    [0] (?)
   NET:Transaction status      [R] (Response)
   NET:Action code             [0] (return card)
   NET:Response code           [00] (Authorised)
   NET:------------------------
   NET:Account number length   [13]
   NET:Account number          [01008198052000000000]
   NET:Display actual balance  [T]
   NET:Actual balance          [000000000000000]
   NET:Display available bal   [T]
   NET:Available balance       [000000000000000]
   NET:TLVX Data Block is present - size [69] bytes.  Field Data:
   NET:TLVX Field [BALCUR]
   NET:38 30 30 00                                      :004:: 800_
   NET:TLVX Field [ACC1TA]
   NET:31 00                                            :002:: 1_
   NET:TLVX Field [ACC1NAME]
   NET:52 41 59 4D 4F 4E 44 20  42 59 41 52 55 48 41 4E :010:: RAYMOND BYARUHAN
   NET:47 41 00                                         :013:: GA_
   NET:TLVX Field [HOSTAUTHID]
   NET:33 37 33 35 32 35                                :006:: 373525
   NET:TLVX Data Block contains 4 fields
   NET:07134584:SPA: RQ OR RSP : [2] [Response]
   NET:07134584:DBLK LO: imd [627923] fun [602] ATMID [9999] branch [0000] seq [1863] 
   NET:07134584:SPA : Determine spa message class:
   NET:07134584:Fun [602], msg class[POS]
   NET:07134584:SPA : analyze_spa_message
   NET:07134584:Terminal Entry method: Magnetic stripe
   NET:07134584:DBLK BASE: amt [000000000000000] acqdev [P] netwk [W] state [R] rspcode [00]
   NET:07134584:SPA: RQ OR RSP : [2] [Response]
   NET:07134584:SPA : Deblocking vdata type [A]
   NET:DBLK BALANCE : account no [0100819805200], act_bal [0.000000], avl_bal [0.000000]
   NET:07134584:SPA: deblock_var_A - AUTH or bal_enq for proc by BDB
   NET:07134584:TC [80] fun [602] err [0] idx [0]
   NET:07134584:ISS: High seq 149 from TPRI      149
   NET:07134584:NETWORK [ABC] START PROCESS ISS TXN
   NET:07134584:***********************************
   NET:07134584:Try to locate txn in Store
   NET:07134584:Request located in STORE slot [1]
   NET:07134584:GEN: ST  [wfrsp](2) EV  [NamQ](80) PR [non fin txn rsp](21) [RSP]
   NET:07134584:ISS: gen_txn_rsp: Authed TXN : auth_id_rsp [491863]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 32 31 30                                      :004:: 0210
   NET:BUILD BM - BCCCbbCUUUCCCUTTUCUUUUUUUUUUUUUCTUUUCTCUCCCUUUUUCTTUUbbUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUbbUUUUUUUUUUUUUUUUUUUUUUUB
   NET:----- Field 2 -----
   NET:F002 DATA PREP [787878******0000]
   NET:ADD LEN: len fmt [1] len len [1] len [16] err [0]
   NET:DATA ADDED
   NET:16 2A 2A 2A 2A 2A 2A 2A  2A                      :009:: _********
   NET:----- Field 3 -----
   NET:F003 DATA PREP [370000]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:37 00 00                                         :003:: 7__
   NET:----- Field 4 -----
   NET:F004 DATA PREP [000000000000]
   NET:ADD LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA ADDED
   NET:00 00 00 00 00 00                                :006:: ______
   NET:----- Field 5 -----
   NET:F005 DATA PREP []
   NET:----- Field 6 -----
   NET:F006 DATA PREP []
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303071340]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 07 13 40                                   :005:: ____@
   NET:----- Field 11 -----
   NET:F011 DATA PREP [601894]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:60 18 94                                         :003:: `__
   NET:----- Field 12 -----
   NET:F012 DATA PREP [071340]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:07 13 40                                         :003:: __@
   NET:----- Field 13 -----
   NET:F013 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 15 -----
   NET:F015 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 16 -----
   NET:F016 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 18 -----
   NET:F018 DATA PREP [5999]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:59 99                                            :002:: Y_
   NET:----- Field 32 -----
   NET:F032 DATA PREP [627923]
   NET:ADD LEN: len fmt [1] len len [1] len [6] err [0]
   NET:DATA ADDED
   NET:06 62 79 23                                      :004:: _by#
   NET:----- Field 33 -----
   NET:F033 DATA PREP []
   NET:----- Field 37 -----
   NET:F037 DATA PREP [716542464491]
   NET:ADD LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA ADDED
   NET:F7 F1 F6 F5 F4 F2 F4 F6  F4 F4 F9 F1             :00C:: ____________
   NET:----- Field 38 -----
   NET:F038 DATA PREP [491863]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:F4 F9 F1 F8 F6 F3                                :006:: ______
   NET:----- Field 39 -----
   NET:F039 DATA PREP [00]
   NET:ADD LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA ADDED
   NET:F0 F0                                            :002:: __
   NET:----- Field 41 -----
   NET:F041 DATA PREP [93649470]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:F9 F3 F6 F4 F9 F4 F7 F0                          :008:: ________
   NET:----- Field 42 -----
   NET:F042 DATA PREP [108464         ]
   NET:ADD LEN: len fmt [0] len len [0] len [15] err [0]
   NET:DATA ADDED
   NET:F1 F0 F8 F4 F6 F4 40 40  40 40 40 40 40 40 40    :00F:: ______@@@@@@@@@
   NET:----- Field 43 -----
   NET:F043 DATA PREP [PEGASUS                             STUG]
   NET:ADD LEN: len fmt [0] len len [0] len [40] err [0]
   NET:DATA ADDED
   NET:D7 C5 C7 C1 E2 E4 E2 40  40 40 40 40 40 40 40 40 :010:: _______@@@@@@@@@
   NET:40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40 :020:: @@@@@@@@@@@@@@@@
   NET:40 40 40 40 E2 E3 E4 C7                          :028:: @@@@____
   NET:----- Field 49 -----
   NET:F049 DATA PREP [800]
   NET:ADD LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA ADDED
   NET:08 00                                            :002:: __
   NET:----- Field 50 -----
   NET:F050 DATA PREP []
   NET:----- Field 51 -----
   NET:F051 DATA PREP []
   NET:----- Field 54 -----
   NET:F054 DATA PREP [0001800C0000000000000002800C000000000000]
   NET:ADD LEN: len fmt [5] len len [2] len [40] err [0]
   NET:DATA ADDED
   NET:00 40 F0 F0 F0 F1 F8 F0  F0 C3 F0 F0 F0 F0 F0 F0 :010:: _@______________
   NET:F0 F0 F0 F0 F0 F0 F0 F0  F0 F2 F8 F0 F0 C3 F0 F0 :020:: ________________
   NET:F0 F0 F0 F0 F0 F0 F0 F0  F0 F0                   :02A:: __________
   NET:----- Field 55 -----
   NET:F055 DATA PREP (MIXED):
   NET:ISO: Completed part [1] of message
   NET:----- Field 103 -----
   NET:F103 DATA PREP [0100819805200]
   NET:ADD LEN: len fmt [1] len len [1] len [13] err [0]
   NET:DATA ADDED
   NET:13 F0 F1 F0 F0 F8 F1 F9  F8 F0 F5 F2 F0 F0       :00E:: ______________
   NET:----- Field 104 -----
   NET:F104 DATA PREP (MIXED):
   NET:C0 06 12 52 41 59 4D 4F  4E 44 20 42 59 41 52 55 :010:: ___RAYMOND BYARU
   NET:48 41 4E 47 41                                   :015:: HANGA
   NET:ADD LEN: len fmt [5] len len [2] len [21] err [0]
   NET:DATA ADDED
   NET:00 21 C0 06 12 52 41 59  4D 4F 4E 44 20 42 59 41 :010:: _!___RAYMOND BYA
   NET:52 55 48 41 4E 47 41                             :017:: RUHANGA
   NET:----- Field 128 -----
   NET:F128 DATA PREP [NNNNNNNN]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:ISO: Completed part [2] of message
   NET:07134584:ISO: Built primary bitmap with err [0]
   NET:07134584:ISO: Built secondary bitmap with err [0]
   NET:07134584:NKY: Net key (from STAN) [1601894030307134000000627923]
   NET:07134585:NETWORK [ABC] END PROCESS ISS TXN
   NET:07134585:***********************************
   NET:07142458:NET RCV
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:30 32 30 30                                      :004:: 0200
   NET:DATA GOT [0200]
   NET:Msg type 200
   NET:07142458:ISO: RCV BM 
   NET:F2 3B 46 81 08 E0 80 00                          :008:: _;F_____
   NET:07142458:ISO: RCV BM 
   NET:00 00 00 00 02 00 01 01                          :008:: ________
   NET:ISO: Skipping F001 - it's a bitmap
   NET:----- Field 2 -----
   NET:GET LEN: len fmt [1] len len [1] len [16] err [0]
   NET:DATA RCVED
   NET:16 2A 2A 2A 2A 2A 2A 2A  2A                      :009:: _********
   NET:F002 DATA GOT [787878******0000]
   NET:----- Field 3 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:37 00 00                                         :003:: 7__
   NET:F003 DATA GOT [370000]
   NET:----- Field 4 -----
   NET:GET LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA RCVED
   NET:00 00 00 00 00 00                                :006:: ______
   NET:F004 DATA GOT [000000000000]
   NET:----- Field 7 -----
   NET:GET LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA RCVED
   NET:03 03 07 14 19                                   :005:: _____
   NET:F007 DATA GOT [0303071419]
   NET:----- Field 11 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:78 53 63                                         :003:: xSc
   NET:F011 DATA GOT [785363]
   NET:----- Field 12 -----
   NET:GET LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA RCVED
   NET:07 14 19                                         :003:: ___
   NET:F012 DATA GOT [071419]
   NET:----- Field 13 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F013 DATA GOT [0303]
   NET:----- Field 15 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F015 DATA GOT [0303]
   NET:----- Field 16 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:03 03                                            :002:: __
   NET:F016 DATA GOT [0303]
   NET:----- Field 18 -----
   NET:GET LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA RCVED
   NET:59 99                                            :002:: Y_
   NET:F018 DATA GOT [5999]
   NET:----- Field 22 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:00 11                                            :002:: __
   NET:F022 DATA GOT [011]
   NET:----- Field 23 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:00 00                                            :002:: __
   NET:F023 DATA GOT [000]
   NET:----- Field 25 -----
   NET:GET LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA RCVED
   NET:05                                               :001:: _
   NET:F025 DATA GOT [05]
   NET:----- Field 32 -----
   NET:GET LEN: len fmt [1] len len [1] len [6] err [0]
   NET:DATA RCVED
   NET:06 62 79 23                                      :004:: _by#
   NET:F032 DATA GOT [627923]
   NET:----- Field 37 -----
   NET:GET LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA RCVED
   NET:F4 F2 F6 F5 F2 F6 F9 F6  F7 F1 F3 F8             :00C:: ____________
   NET:F037 DATA GOT [426526967138]
   NET:----- Field 41 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:F9 F3 F6 F4 F9 F4 F7 F0                          :008:: ________
   NET:F041 DATA GOT [93649470]
   NET:----- Field 42 -----
   NET:GET LEN: len fmt [0] len len [0] len [15] err [0]
   NET:DATA RCVED
   NET:F1 F0 F8 F4 F6 F4 40 40  40 40 40 40 40 40 40    :00F:: ______@@@@@@@@@
   NET:F042 DATA GOT [108464         ]
   NET:----- Field 43 -----
   NET:GET LEN: len fmt [0] len len [0] len [40] err [0]
   NET:DATA RCVED
   NET:D7 C5 C7 C1 E2 E4 E2 40  40 40 40 40 40 40 40 40 :010:: _______@@@@@@@@@
   NET:40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40 :020:: @@@@@@@@@@@@@@@@
   NET:40 40 40 40 E2 E3 E4 C7                          :028:: @@@@____
   NET:F043 DATA GOT [PEGASUS                             STUG]
   NET:----- Field 49 -----
   NET:GET LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA RCVED
   NET:08 00                                            :002:: __
   NET:F049 DATA GOT [800]
   NET:ISO: Skipping F065 - it's a bitmap
   NET:----- Field 103 -----
   NET:GET LEN: len fmt [1] len len [1] len [13] err [0]
   NET:DATA RCVED
   NET:13 F0 F1 F0 F0 F8 F0 F5  F1 F1 F7 F4 F0 F0       :00E:: ______________
   NET:F103 DATA GOT [0100805117400]
   NET:----- Field 120 -----
   NET:GET LEN: len fmt [5] len len [2] len [4] err [0]
   NET:DATA RCVED
   NET:00 04 C4 D7 D6 E2                                :006:: ______
   NET:F120 DATA GOT [DPOS]
   NET:----- Field 128 -----
   NET:GET LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA RCVED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:F128 DATA GOT [NNNNNNNN]
   NET:07142458:NKY: Net key (from STAN) [1785363030307141900000627923]
   NET:07142458:TC [80] NET MSGT [200] SPA MSGT [602]
   NET:07142458:NET: net_process_mac, ISS, RQ, KEK USER [ABC]
   NET:07142458:NET: MAC Process: Return [0]
   NET:07142458:NETWORK [ABC] START PROCESS ISS TXN
   NET:07142458:***********************************
   NET:07142458:Try to locate txn in Store
   NET:07142458:Looking up txn using NET key
   NET:07142458:No match in disk log
   NET:07142458:Slot [1] allocated in store
   NET:07142458:GEN: ST  [newstore](0) EV  [NamQ](80) PR [txn rq](1) [RQ]
   NET:07142458:Expected rq bm [RRDROORUUURRDOOOURUUUDOURUUUUUUDOUdURUUURRRUUUUUROOdUUdUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUdOUUOOOUUOUUUUUUUURUUUUUUUR]
   NET:F001 expctd [R] rcvd [P] 
   NET:F002 expctd [R] rcvd [P] 
   NET:F003 expctd [D] rcvd [P] 
   NET:F004 expctd [R] rcvd [P] 
   NET:F005 expctd [O] rcvd [U] 
   NET:F006 expctd [O] rcvd [U] 
   NET:F007 expctd [R] rcvd [P] 
   NET:F011 expctd [R] rcvd [P] 
   NET:F012 expctd [R] rcvd [P] 
   NET:F013 expctd [D] rcvd [P] 
   NET:F014 expctd [O] rcvd [U] 
   NET:F015 expctd [O] rcvd [P] 
   NET:F016 expctd [O] rcvd [P] 
   NET:F018 expctd [R] rcvd [P] 
   NET:F022 expctd [D] rcvd [P] 
   NET:POS Entry Mode (Network format): [011]
   NET:POS Entry Mode (Sparrow format): [011]
   NET:F023 expctd [O] rcvd [P] 
   NET:F025 expctd [R] rcvd [P] 
   NET:F032 expctd [D] rcvd [P] 
   NET:F033 expctd [O] rcvd [U] 
   NET:F035 expctd [d] rcvd [U] 
   NET:F037 expctd [R] rcvd [P] 
   NET:F041 expctd [R] rcvd [P] 
   NET:F042 expctd [R] rcvd [P] 
   NET:F043 expctd [R] rcvd [P] 
   NET:F049 expctd [R] rcvd [P] 
   NET:F050 expctd [O] rcvd [U] 
   NET:F051 expctd [O] rcvd [U] 
   NET:F052 expctd [d] rcvd [U] 
   NET:F055 expctd [d] rcvd [U] 
   NET:F102 expctd [d] rcvd [U] 
   NET:F103 expctd [O] rcvd [P] 
   NET:F106 expctd [O] rcvd [U] 
   NET:F107 expctd [O] rcvd [U] 
   NET:F108 expctd [O] rcvd [U] 
   NET:F111 expctd [O] rcvd [U] 
   NET:F120 expctd [R] rcvd [P] 
   NET:F128 expctd [R] rcvd [P] 
   NET:07142458:ISS: Build variable data type [X] for msg type [200]
   NET:07142458:ISS: build_type_netx 112v3
   NET:07142458:No expiry date supplied - zero-filling T2
   NET:07142458:ISS: Performing licenced issuer IMD 787878 check
   NET:07142458:TLVX: Added 59 byte TLVX Data Block - Var Data Type [x]
   NET:07142458:ISS: REQ TO HOST LO_MSG: 
   NET:07142458:IMD:627923 800 0000 Id:9999 Seq:1864
   NET:07142458:Fun:(602) On/Off:[Auth(&Post)] Date:260303 Time:071419
   NET:602 Network Request X Type (net_ext_type v1.12.3)
   NET:Variable data type      [x]
   NET:Index                   [01]
   NET:Track 2                 [787878******0000*****                ]
   NET:Txn (dispense) amount   [000000000000000]
   NET:Txn (dispense) curr code[800]
   NET:ISO TA (account type)   [0]
   NET:PIN block format        [00]
   NET:PIN block               [XXXXXXXXXXXXXXXX]
   NET:Acquiring device        [P]
   NET:Network code            [W]
   NET:Language code           [1]
   NET:Action for PIN block    [I] (Ignore)
   NET:Transaction status      [r] (Request)
   NET:Action code             [0] (return card)
   NET:Response code           [00] (Authorised)
   NET:------------------------
   NET:NET extension version   [03]
   NET:External network ID     [ABC]
   NET:Authorisation code      [491864]
   NET:Acq institution ID      [627923     ]
   NET:Forwarding inst ID      [           ]
   NET:Merchant category code  [5999]
   NET:Card acceptor term ID   [93649470        ]
   NET:Card acceptor ID        [108464         ]
   NET:Card acceptor name/loc  [PEGASUS                             STUG]
   NET:Currency code billing   [000]
   NET:Transaction amount bill [+00000000000000]
   NET:Conversion rate billing [61000000]
   NET:Cashback amount billing [+00000000000000]
   NET:Cashback amount device  [+00000000000000]
   NET:Cashback amnt src acct  [+00000000000000]
   NET:Settlement currency     [000]
   NET:Settlement amount       [+00000000000000]
   NET:Conversion rate settl   [61000000]
   NET:Actual balance          [+00000000000000]
   NET:Available balance       [+00000000000000]
   NET:Retrieval reference no  [426526967138]
   NET:Systems trace audit no  [785363]
   NET:Transaction ID          [000000000000000]
   NET:TLVX Data Block is present - size [59] bytes.  Field Data:
   NET:TLVX Field [NETPOSEM]
   NET:30 31 31 00                                      :004:: 011_
   NET:TLVX Field [ACC1SRC]
   NET:48                                               :001:: H
   NET:TLVX Field [ACC1NO]
   NET:30 31 30 30 38 30 35 31  31 37 34 30 30 00       :00E:: 0100805117400_
   NET:TLVX Field [CHCODE]
   NET:44 50 4F 53 00                                   :005:: DPOS_
   NET:TLVX Data Block contains 4 fields
   NET:07142458:NETWORK [ABC] END PROCESS ISS TXN
   NET:07142458:***********************************
   NET:07142484:Read IMT_LOMSG
   NET:07142484:SPA RCV: 
   NET:07142484:IMD:627923 800 0000 Id:9999 Seq:1864
   NET:07142484:Fun:(602) On/Off:[Auth(&Post)] Date:260303 Time:071419
   NET:602 Network Auth Response A Type (na_type)
   NET:Variable data type      [a]
   NET:Index                   [00]
   NET:Track 2                 [787878*********0000                  ]
   NET:Txn (dispense) amount   [+00000000000000]
   NET:Txn (dispense) curr code[800]
   NET:ISO TA (account type)   [1]
   NET:PIN block format        [00]
   NET:PIN block               [XXXXXXXXXXXXXXXX]
   NET:Acquiring device        [P]
   NET:Network code            [W]
   NET:Language code           [0]
   NET:Action for PIN block    [0] (?)
   NET:Transaction status      [R] (Response)
   NET:Action code             [0] (return card)
   NET:Response code           [00] (Authorised)
   NET:------------------------
   NET:Account number length   [13]
   NET:Account number          [01008051174000000000]
   NET:Display actual balance  [T]
   NET:Actual balance          [000000000000000]
   NET:Display available bal   [T]
   NET:Available balance       [000000000000000]
   NET:TLVX Data Block is present - size [62] bytes.  Field Data:
   NET:TLVX Field [BALCUR]
   NET:38 30 30 00                                      :004:: 800_
   NET:TLVX Field [ACC1TA]
   NET:31 00                                            :002:: 1_
   NET:TLVX Field [ACC1NAME]
   NET:4D 4F 53 45 53 20 53 53  4F 5A 49 00             :00C:: MOSES SSOZI_
   NET:TLVX Field [HOSTAUTHID]
   NET:33 37 33 35 32 36                                :006:: 373526
   NET:TLVX Data Block contains 4 fields
   NET:07142484:SPA: RQ OR RSP : [2] [Response]
   NET:07142484:DBLK LO: imd [627923] fun [602] ATMID [9999] branch [0000] seq [1864] 
   NET:07142484:SPA : Determine spa message class:
   NET:07142484:Fun [602], msg class[POS]
   NET:07142484:SPA : analyze_spa_message
   NET:07142484:Terminal Entry method: Magnetic stripe
   NET:07142484:DBLK BASE: amt [000000000000000] acqdev [P] netwk [W] state [R] rspcode [00]
   NET:07142484:SPA: RQ OR RSP : [2] [Response]
   NET:07142484:SPA : Deblocking vdata type [A]
   NET:DBLK BALANCE : account no [0100805117400], act_bal [0.000000], avl_bal [0.000000]
   NET:07142484:SPA: deblock_var_A - AUTH or bal_enq for proc by BDB
   NET:07142484:TC [80] fun [602] err [0] idx [0]
   NET:07142484:ISS: High seq 149 from TPRI      149
   NET:07142484:NETWORK [ABC] START PROCESS ISS TXN
   NET:07142484:***********************************
   NET:07142484:Try to locate txn in Store
   NET:07142484:Request located in STORE slot [1]
   NET:07142484:GEN: ST  [wfrsp](2) EV  [NamQ](80) PR [non fin txn rsp](21) [RSP]
   NET:07142484:ISS: gen_txn_rsp: Authed TXN : auth_id_rsp [491864]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:30 32 31 30                                      :004:: 0210
   NET:BUILD BM - BCCCbbCUUUCCCUTTUCUUUUUUUUUUUUUCTUUUCTCUCCCUUUUUCTTUUbbUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUbbUUUUUUUUUUUUUUUUUUUUUUUB
   NET:----- Field 2 -----
   NET:F002 DATA PREP [787878******0000]
   NET:ADD LEN: len fmt [1] len len [1] len [16] err [0]
   NET:DATA ADDED
   NET:16 2A 2A 2A 2A 2A 2A 2A  2A                      :009:: _********
   NET:----- Field 3 -----
   NET:F003 DATA PREP [370000]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:37 00 00                                         :003:: 7__
   NET:----- Field 4 -----
   NET:F004 DATA PREP [000000000000]
   NET:ADD LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA ADDED
   NET:00 00 00 00 00 00                                :006:: ______
   NET:----- Field 5 -----
   NET:F005 DATA PREP []
   NET:----- Field 6 -----
   NET:F006 DATA PREP []
   NET:----- Field 7 -----
   NET:F007 DATA PREP [0303071419]
   NET:ADD LEN: len fmt [0] len len [0] len [10] err [0]
   NET:DATA ADDED
   NET:03 03 07 14 19                                   :005:: _____
   NET:----- Field 11 -----
   NET:F011 DATA PREP [785363]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:78 53 63                                         :003:: xSc
   NET:----- Field 12 -----
   NET:F012 DATA PREP [071419]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:07 14 19                                         :003:: ___
   NET:----- Field 13 -----
   NET:F013 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 15 -----
   NET:F015 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 16 -----
   NET:F016 DATA PREP [0303]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:03 03                                            :002:: __
   NET:----- Field 18 -----
   NET:F018 DATA PREP [5999]
   NET:ADD LEN: len fmt [0] len len [0] len [4] err [0]
   NET:DATA ADDED
   NET:59 99                                            :002:: Y_
   NET:----- Field 32 -----
   NET:F032 DATA PREP [627923]
   NET:ADD LEN: len fmt [1] len len [1] len [6] err [0]
   NET:DATA ADDED
   NET:06 62 79 23                                      :004:: _by#
   NET:----- Field 33 -----
   NET:F033 DATA PREP []
   NET:----- Field 37 -----
   NET:F037 DATA PREP [426526967138]
   NET:ADD LEN: len fmt [0] len len [0] len [12] err [0]
   NET:DATA ADDED
   NET:F4 F2 F6 F5 F2 F6 F9 F6  F7 F1 F3 F8             :00C:: ____________
   NET:----- Field 38 -----
   NET:F038 DATA PREP [491864]
   NET:ADD LEN: len fmt [0] len len [0] len [6] err [0]
   NET:DATA ADDED
   NET:F4 F9 F1 F8 F6 F4                                :006:: ______
   NET:----- Field 39 -----
   NET:F039 DATA PREP [00]
   NET:ADD LEN: len fmt [0] len len [0] len [2] err [0]
   NET:DATA ADDED
   NET:F0 F0                                            :002:: __
   NET:----- Field 41 -----
   NET:F041 DATA PREP [93649470]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:F9 F3 F6 F4 F9 F4 F7 F0                          :008:: ________
   NET:----- Field 42 -----
   NET:F042 DATA PREP [108464         ]
   NET:ADD LEN: len fmt [0] len len [0] len [15] err [0]
   NET:DATA ADDED
   NET:F1 F0 F8 F4 F6 F4 40 40  40 40 40 40 40 40 40    :00F:: ______@@@@@@@@@
   NET:----- Field 43 -----
   NET:F043 DATA PREP [PEGASUS                             STUG]
   NET:ADD LEN: len fmt [0] len len [0] len [40] err [0]
   NET:DATA ADDED
   NET:D7 C5 C7 C1 E2 E4 E2 40  40 40 40 40 40 40 40 40 :010:: _______@@@@@@@@@
   NET:40 40 40 40 40 40 40 40  40 40 40 40 40 40 40 40 :020:: @@@@@@@@@@@@@@@@
   NET:40 40 40 40 E2 E3 E4 C7                          :028:: @@@@____
   NET:----- Field 49 -----
   NET:F049 DATA PREP [800]
   NET:ADD LEN: len fmt [0] len len [0] len [3] err [0]
   NET:DATA ADDED
   NET:08 00                                            :002:: __
   NET:----- Field 50 -----
   NET:F050 DATA PREP []
   NET:----- Field 51 -----
   NET:F051 DATA PREP []
   NET:----- Field 54 -----
   NET:F054 DATA PREP [0001800C0000000000000002800C000000000000]
   NET:ADD LEN: len fmt [5] len len [2] len [40] err [0]
   NET:DATA ADDED
   NET:00 40 F0 F0 F0 F1 F8 F0  F0 C3 F0 F0 F0 F0 F0 F0 :010:: _@______________
   NET:F0 F0 F0 F0 F0 F0 F0 F0  F0 F2 F8 F0 F0 C3 F0 F0 :020:: ________________
   NET:F0 F0 F0 F0 F0 F0 F0 F0  F0 F0                   :02A:: __________
   NET:----- Field 55 -----
   NET:F055 DATA PREP (MIXED):
   NET:ISO: Completed part [1] of message
   NET:----- Field 103 -----
   NET:F103 DATA PREP [0100805117400]
   NET:ADD LEN: len fmt [1] len len [1] len [13] err [0]
   NET:DATA ADDED
   NET:13 F0 F1 F0 F0 F8 F0 F5  F1 F1 F7 F4 F0 F0       :00E:: ______________
   NET:----- Field 104 -----
   NET:F104 DATA PREP (MIXED):
   NET:C0 06 0B 4D 4F 53 45 53  20 53 53 4F 5A 49       :00E:: ___MOSES SSOZI
   NET:ADD LEN: len fmt [5] len len [2] len [14] err [0]
   NET:DATA ADDED
   NET:00 14 C0 06 0B 4D 4F 53  45 53 20 53 53 4F 5A 49 :010:: _____MOSES SSOZI
   NET:----- Field 128 -----
   NET:F128 DATA PREP [NNNNNNNN]
   NET:ADD LEN: len fmt [0] len len [0] len [8] err [0]
   NET:DATA ADDED
   NET:4E 4E 4E 4E 4E 4E 4E 4E                          :008:: NNNNNNNN
   NET:ISO: Completed part [2] of message
   NET:07142484:ISO: Built primary bitmap with err [0]
   NET:07142484:ISO: Built secondary bitmap with err [0]
   NET:07142484:NKY: Net key (from STAN) [1785363030307141900000627923]
   NET:07142484:NETWORK [ABC] END PROCESS ISS TXN
   NET:07142484:***********************************
   NET:07143302:Message store is 0 percent used
   NET:07143302:SAF (ISS): no txns extracted from SAF
   NET:07144801:Message store is 0 percent used
   NET:07144801:SAF (ACQ): no txns extracted from SAF
   NET:07152501:NM RQ[echo_test] from FG
   NET:07152501:NETWORK [ABC] START PROCESS ACQ TXN
   NET:07152501:***********************************
*/
