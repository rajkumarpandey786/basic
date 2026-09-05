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
--mapping_updated_fields_withc400-tsaas.txt
root.rec.AcceptorLegalBusinessName= details.acceptorLegalBusinessName
root.rec.AcqCountryCode= details.acquiringCountryCode
root.rec.AcqInstID= details.institutionCode
root.rec.AdditionalMsg= details.additionalMessage
root.rec.BillingAmt= details.holderBillingAmount
root.rec.BillingCurrCode= details.cardHolderCurrency
root.rec.CardNbr= details.pan
root.rec.CardSeqNbr= NO_EXISTS
root.rec.Chnl= NO_EXISTS
root.rec.Country= details.country
root.rec.FundingSource= details.fundingSource
root.rec.FunctionName= NO_EXISTS
root.rec.LanguageData= NO_EXISTS
root.rec.LanguageID= NO_EXISTS
root.rec.LocalTrxnDate= details.transactionDate
root.rec.LocalTrxnTime= NO_EXISTS
root.rec.MCC= NO_EXISTS
root.rec.MTI= details.msgType
root.rec.MerchantID= NO_EXISTS
root.rec.MerchantName= details.cardAcceptName
root.rec.OBSResult1= details.obService2
root.rec.OBService= details.obService1
root.rec.POSEntryMode= NO_EXISTS
root.rec.POSConditionCode= NO_EXISTS
root.rec.ParticipationID= NO_EXISTS
root.rec.PaymentFacilitatorName= details.paymentFacilitatorName
root.rec.ProcessingCode= details.processingCode
root.rec.RecipientAcctNbr= details.recipientAcctNumber
root.rec.RecipientAddr= details.recipientAddress
root.rec.RecipientCity= details.recipientCity
root.rec.RecipientCountry= details.recipientCountry
root.rec.RecipientCountryOfBirth= details.recipientCob
root.rec.RecipientDOB= details.recipientDob
root.rec.RecipientID= details.recipientIdtNo
root.rec.RecipientIDCountryCode= details.recipientIdtCc
root.rec.RecipientIDExpDate= details.recipientExpiry
root.rec.RecipientIDType= details.recipientIdType
root.rec.RecipientName= details.recipientName
root.rec.RecipientNationality= details.recipientNationality
root.rec.RecipientPhoneNbr= NO_EXISTS
root.rec.RecipientPostalCode= details.recipientPostalCode
root.rec.RecipientState= details.provinceCode
root.rec.ReqID= NO_EXISTS
root.rec.RetrievalRefNbr= details.referenceNumber
root.rec.SchemeTrxnID= NO_EXISTS
root.rec.ScreeningScore= NO_EXISTS
root.rec.SenderAcctNbr= details.senderAccount
root.rec.SenderAddr= details.senderAddress
root.rec.SenderCity= details.senderCity
root.rec.SenderCountry= details.senderCountry
root.rec.SenderCountryOfBirth= details.sendCob
root.rec.SenderDOB= details.senderDob
root.rec.SenderID= details.senderIdNumber
root.rec.SenderIDCountryCode= details.senderIdCountryCode
root.rec.SenderIDExpDate= NO_EXISTS
root.rec.SenderIDType= NO_EXISTS
root.rec.SenderName= details.senderName
root.rec.SenderNationality= details.senderNationality
root.rec.SenderPhoneNbr= NO_EXISTS
root.rec.SenderPostalCode= details.senderPostalCode
root.rec.SenderState= details.senderState
root.rec.SysTrace= NO_EXISTS
root.rec.TerminalID= details.institutionId
root.rec.TransmissionDateTime= NO_EXISTS
root.rec.TrxnAmt= details.txnAmount
root.rec.TrxnCatCode= details.paymentType
root.rec.TrxnCurrCode= details.currency
root.rec.TrxnPurpose= details.transactionPurpose
root.rec.TrxnType= type
root.rec.UniqueTrxnRef= details.senderRef
root.rec.WLMResultsCode= NO_EXISTS
root.rec.externalTransactionId= uuMid
root.rec.status= NO_EXISTS
root.rec.type= txntype
---- tsaas_updated_Request.txt
{
    "uuMid": "1d4b2a31-8ad6-4073-a2e7-70d334a50111",
    "unit": "CPH",
    "business": "C400",
    "application": "CPH",
    "type": "OCT",
    "service": "NA",
    "userRef": "NA",
    "direction": "I",
    "reference": "312216287796",
    "details": {
        "msgType": "0200",
        "sid": null,
        "cid": "C400",
        "country": "SG",
        "paymentServiceField": null,
        "pan": "1787301538525",
        "processingCode": "260000",
        "txnAmount": "000006.00",
        "holderBillingAmount": "00006.00",
        "conversionRateHolder": null,
        "acquiringCountryCode": "GH",
        "institutionCode": "1234",
        "referenceNumber": "312216287796",
        "cardAcceptName": "MERCHANTNAME",
        "currency": "936",
        "cardHolderCurrency": "936",
        "senderRef": "UNIQREF123",
        "senderAccount": "312216287796",
        "senderName": "ROB",
        "recipientName": "Joseph",
        "senderCity": "UK",
        "senderState": "UK",
        "senderCountry": "GH",
        "sourceOfFund": null,
        "transactionDate": "061225",
        "addlData": null,
        "paymentType": null,
        "obService1": "211",
        "obService2": "00",
        "firstName": "Joseph",
        "middleName": null,
        "lastName": null,
        "streetAddress": "ADD",
        "recipientCity": "UK",
        "provinceCode": "UK",
        "recipientCountry": "GH",
        "recipientPostalCode": "TEST",
        "recipientDob": "23124",
        "recipientAcctNumber": "Test",
        "senderFirstName": "ROB",
        "senderMiddleName": null,
        "senderLastName": null,
        "senderPostalCode": "0121",
        "senderAddress": "ROB ADD",
        "additionalMessage": "TESTTING",
        "fundingSource": "02",
        "institutionId": "TERM1234",
        "senderIdNumber": "212",
        "senderNationality": "UK",
        "sendCob": "35222",
        "senderDob": "099112",
        "senderIdCountryCode": "221",
        "recipientAddress": "ADD",
        "recipientIdType": "TWA",
        "recipientIdtNo": "992",
        "recipientIdtCc": "2232",
        "recipientExpiry": "asd",
        "recipientNationality": "II",
        "recipientCob": "213132",
        "transactionPurpose": "TEST",
        "bin": null,
        "acceptorLegalBusinessName": null,
        "paymentFacilitatorName": null,
        "trxnType": null,
        "sbitmap": null,
        "pbitmap": null
    },
    "recipientName": "Joseph",
    "senderName": "ROB",
    "msgType": "0200",
    "sendCob": "35222",
    "pan": "1787301538525",
    "country": "SG",
    "referenceNumber": "312216287796",
    "streetAddress": "ADD",
    "recipientCity": "UK",
    "provinceCode": "UK",
    "senderAddress": "ROB ADD",
    "senderCountry": "GH",
    "senderCity": "UK",
    "senderAccount": "312216287796",
    "recipientDob": "23124",
    "senderFirstName": "ROB",
    "senderState": "UK",
    "senderDob": "099112",
    "txnAmount": "000006.00",
    "firstName": "Joseph",
    "cardAcceptName": "MERCHANTNAME",
    "processingCode": "260000",
    "transactionDate": "061225",
    "acquiringCountryCode": "GH",
    "recipientCountry": "GH",
    "senderPostalCode": "0121",
    "recipientAddress": "ADD",
    "senderNationality": "UK",
    "senderIdCountryCode": "221",
    "recipientPostalCode": "TEST",
    "cardHolderCurrency": "936",
    "holderBillingAmount": "00006.00",
    "institutionCode": "1234",
    "recipientIdTNo": "992",
    "recipientIdTCc": "2232",
    "recipientExpiry": "asd",
    "senderIdNumber": "212",
    "recipientCob": "213132",
    "obService1": "211",
    "fundingSource": "02",
    "institutionId": "TERM1234",
    "senderRef": "UNIQREF123",
    "obService2": "00",
    "recipientIdType": "TWA",
    "cid": "C400",
    "recipientAcctNumber": "Test",
    "recipientNationality": "II",
    "additionalMessage": "TESTTING",
    "transactionPurpose": "TEST",
    "currency": "936",
    "txntype": "CB",
    "valuedate": "061225",
    "SENDER": "CPH",
    "RECEIVER": "TSAAS"
}'
------resp_mapping.txt
root.rec.Chnl 						=  NO_EXISTS 
root.rec.Country 					=  NO_EXISTS 
root.rec.FunctionName 				=  NO_EXISTS
root.rec.ReqID 						=  systemID
root.rec.Ostatus				    =  responseCode
root.rec.RespMsg                    =  messageStatus
root.rec.externalTransactionId      =  transactionReferenceNumber
root.rec.ErrorCode					=  NO_EXISTS
root.rec.ErrorDesc 					=  NO_EXISTS
NO_EXISTS 					        =  responseDescription
NO_EXISTS                           =  callbackUrl
NO_EXISTS                           =  screeningRequestDate
NO_EXISTS							=  messageChecksum
NO_EXISTS							=  statusOwner
NO_EXISTS                           =  statusComment
NO_EXISTS                           =  statusLabel
----req_mapping.txt
root.rec.AcceptorLegalBusinessName 		 =   acceptorLegalBusinessName  
root.rec.AcqCountryCode					 =   acquiringcountrycode 
root.rec.AcqInstID						 =   NO_EXISTS
root.rec.AdditionalMsg					 =   transaction.details[o].additionalmessage
root.rec.BillingAmt						 =   NO_EXISTS 
root.rec.BillingCurrCode				 =   NO_EXISTS
root.rec.CardNbr						 =   NO_EXISTS
root.rec.CardSeqNbr						 =   NO_EXISTS 
root.rec.Chnl							 =   NO_EXISTS 
root.rec.Country						 =   country 
root.rec.FundingSource					 =   NO_EXISTS
root.rec.FunctionName					 =   NO_EXISTS   
root.rec.LanguageData					 =   NO_EXISTS 
root.rec.LanguageID						 =   NO_EXISTS 
root.rec.LocalTrxnDate					 =   NO_EXISTS  
root.rec.LocalTrxnTime					 =   NO_EXISTS
root.rec.MCC							 =   NO_EXISTS 
root.rec.MTI							 =   NO_EXISTS 
root.rec.MerchantID						 =   NO_EXISTS  
root.rec.MerchantName					 =   transaction.details[B].cardacceptname
root.rec.OBSResult1 					 =   NO_EXISTS 
root.rec.OBService						 =   NO_EXISTS 
root.rec.POSEntryMode					 =   NO_EXISTS   
root.rec.POSConditionCode				 =   NO_EXISTS  
root.rec.ParticipationID				 =   NO_EXISTS 
root.rec.PaymentFacilitatorName			 =   paymentFacilitatorName
root.rec.ProcessingCode					 =   NO_EXISTS  
root.rec.RecipientAcctNbr				 =   transaction.details[P].recipientacctnumber
root.rec.RecipientAddr					 =	 transaction.details[P].receipientaddress
root.rec.RecipientCity					 =	 transaction.details[P].recipientcity
root.rec.RecipientCountry				 =	 transaction.details[B].recipientcountry
root.rec.RecipientCountryOfBirth		 =   recipientcob
root.rec.RecipientDOB					 =   NO_EXISTS 
root.rec.RecipientID					 =   recipientidtno
root.rec.RecipientIDCountryCode			 =   recipientidtcc
root.rec.RecipientIDExpDate				 =   recipientexpiry
root.rec.RecipientIDType				 =   NO_EXISTS 
root.rec.RecipientName					 =	 transaction.details[P].recipientname
root.rec.RecipientNationality			 =   recipientnationality
root.rec.RecipientPhoneNbr				 =   NO_EXISTS 
root.rec.RecipientPostalCode			 =	 recipientpostalcode
root.rec.RecipientState 				 = 	 provincecode
root.rec.ReqID							 =   NO_EXISTS 
root.rec.RetrievalRefNbr				 =	 referenceNumber  
root.rec.SchemeTrxnID					 =   NO_EXISTS  
root.rec.ScreeningScore					 =   NO_EXISTS 
root.rec.SenderAcctNbr					 =   transaction.details[c].senderaccount 
root.rec.SenderAddr						 =   transaction.details[p].senderaddress
root.rec.SenderCity						 =   sendercity
root.rec.SenderCountry					 =   transaction.details[c].sendercountry
root.rec.SenderCountryOfBirth			 =   sendcob
root.rec.SenderDOB						 =   NO_EXISTS 
root.rec.SenderID						 =   transaction.details[c].senderidnumber
root.rec.SenderIDCountryCode			 =   senderidcountrycode
root.rec.SenderIDExpDate				 =   NO_EXISTS 
root.rec.SenderIDType					 =   NO_EXISTS 
root.rec.SenderName						 =   transaction.details[c].sendername
root.rec.SenderNationality				 =   sendernationality
root.rec.SenderPhoneNbr					 =   NO_EXISTS 
root.rec.SenderPostalCode				 =   senderpostalcode
root.rec.SenderState					 =   senderstate
root.rec.SysTrace						 =   NO_EXISTS  
root.rec.TerminalID						 =   NO_EXISTS  
root.rec.TransmissionDateTime			 =   NO_EXISTS  
root.rec.TrxnAmt						 =   transaction.amount
root.rec.TrxnCatCode					 =   NO_EXISTS 
root.rec.TrxnCurrCode					 =   transaction.currency
root.rec.TrxnPurpose					 =   transactionpurpose
root.rec.TrxnType						 =   transaction.product
root.rec.UniqueTrxnRef					 =   NO_EXISTS 
root.rec.WLMResultsCode					 =   NO_EXISTS 
root.rec.externalTransactionId			 =   NO_EXISTS 
root.rec.status							 =   NO_EXISTS 
root.rec.type							 =   details[c].transactionType
NO_EXISTS								 =   bin
--------------
root.rec.Chnl 						=  NO_EXISTS 
root.rec.Country 					=  NO_EXISTS 
root.rec.FunctionName 				=  NO_EXISTS
root.rec.ReqID 						=  systemID
root.rec.Ostatus				    =  responseCode
root.rec.RespMsg                    =  messageStatus
root.rec.externalTransactionId      =  transactionReferenceNumber
root.rec.ErrorCode					=  NO_EXISTS
root.rec.ErrorDesc 					=  NO_EXISTS
NO_EXISTS 					        =  responseDescription
NO_EXISTS                           =  callbackUrl
NO_EXISTS                           =  screeningRequestDate
NO_EXISTS							=  messageChecksum
NO_EXISTS							=  statusOwner
NO_EXISTS                           =  statusComment
NO_EXISTS                           =  statusLabel


----------------
{
    "callbackUrl": " https://gateway-stg.51242.app.standardchartered.com/functions/api/v1/txnscreeningstatus/60dad0eb59664095b7c52126%22",
    "messageChecksum": "",
    "messageStatus": "001",
    "responseCode": "200",
    "responseDescription": "Ack Sent Successfully",
    "screeningRequestDate": "04-Mar-26 05:39:34 AM",
    "statusComment": "Stop: 1, Nonblocking: 0",
    "statusLabel": "HIT",
    "statusOwner": null,
    "systemID": "SBCI20260304053934-00000-1151356",
    "transactionReferenceNumber": "TS_REF_39"
}
*/
