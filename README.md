<!-- C400 REQUEST TO CPH -->    
<root>
    <rec>
        <Country>GH</Country>
        <ReqID>notifyTSAS</ReqID>
        <FunctionName>CPHTSAAS</FunctionName>
        <externalTransactionId>TSA288202305030021090000001542</externalTransactionId>
        <Chnl>TSAS</Chnl>
		<type>DOM</type>	<!-- DOM - Domestic / CB - Cross Border -->    
		<status>Approve</status>	<!-- Approve / Decline -->    	
        <MTI>0100</MTI>
        <CardNbr>486056******8643</CardNbr>
        <ProcessingCode>260000</ProcessingCode>
        <TrxnAmt>0000000006.00</TrxnAmt>
        <BillingAmt>0000000006.00</BillingAmt>
        <TransmissionDateTime>0502162109</TransmissionDateTime>
        <SysTrace>287796</SysTrace>
        <LocalTrxnTime>000000</LocalTrxnTime>
        <LocalTrxnDate>0000</LocalTrxnDate>
        <MCC>4829</MCC>
        <AcqCountryCode>288</AcqCountryCode>
        <POSEntryMode>010</POSEntryMode>
        <CardSeqNbr>0</CardSeqNbr>
        <POSConditionCode>59</POSConditionCode>
        <AcqInstID>416080</AcqInstID>
        <RetrievalRefNbr>312216287796</RetrievalRefNbr>
        <TerminalID>EXPAYGH</TerminalID>
        <MerchantID>EXPAYGH</MerchantID>
        <MerchantName>exPay Accra GH</MerchantName>
        <TrxnCatCode></TrxnCatCode>
        <OBService></OBService>
        <OBSResult1></OBSResult1>
        <ScreeningScore></ScreeningScore>
        <WLMResultsCode></WLMResultsCode>
        <TrxnCurrCode>936</TrxnCurrCode>
        <BillingCurrCode>936</BillingCurrCode>
        <SchemeTrxnID>583122588698861</SchemeTrxnID>
        <TrxnType>PP</TrxnType>
        <UniqueTrxnRef></UniqueTrxnRef>
        <SenderAcctNbr>312216287796</SenderAcctNbr>
        <SenderName></SenderName>
        <SenderAddr></SenderAddr>
        <SenderCity></SenderCity>
		<SenderState></SenderState>
        <SenderCountry>GHA</SenderCountry>
        <FundingSource>02</FundingSource>
        <SenderPostalCode></SenderPostalCode>
        <SenderPhoneNbr></SenderPhoneNbr>
        <SenderDOB></SenderDOB>
        <SenderIDType></SenderIDType>
        <SenderID></SenderID>
        <SenderIDCountryCode></SenderIDCountryCode>
        <SenderIDExpDate></SenderIDExpDate>
        <SenderNationality></SenderNationality>
        <SenderCountryOfBirth></SenderCountryOfBirth>
        <RecipientName>Joseph Ampah</RecipientName>
        <RecipientAddr></RecipientAddr>
        <RecipientCity></RecipientCity>
        <RecipientState></RecipientState>
        <RecipientCountry>GHA</RecipientCountry>
        <RecipientPostalCode></RecipientPostalCode>
        <RecipientPhoneNbr></RecipientPhoneNbr>
        <RecipientDOB></RecipientDOB>
        <RecipientAcctNbr></RecipientAcctNbr>
        <RecipientIDType></RecipientIDType>
        <RecipientID></RecipientID>
        <RecipientIDCountryCode></RecipientIDCountryCode>
        <RecipientIDExpDate></RecipientIDExpDate>
        <RecipientNationality></RecipientNationality>
        <RecipientCountryOfBirth></RecipientCountryOfBirth>
        <AdditionalMsg></AdditionalMsg>
        <ParticipationID></ParticipationID>
        <TrxnPurpose></TrxnPurpose>
        <LanguageID></LanguageID>
        <LanguageData></LanguageData>
		<AcceptorLegalBusinessName>UN</AcceptorLegalBusinessName>
		<PaymentFacilitatorName>UN</PaymentFacilitatorName>
    </rec>
</root>


<!-- C400 RESPONSE FROM CPH -->    
<root>
	<rec>
		<Country>AE</Country>
		<ReqID>notifyTSAS</ReqID>
		<FunctionName>CPHTSAAS</FunctionName>
		<Chnl>TSAS</Chnl>
		<externalTransactionId>TSA784202604092340380000000001</externalTransactionId>
		<Ostatus>00</Ostatus>
		<RespMsg>APPROVED</RespMsg>
		<ErrorCode></ErrorCode>
		<ErrorDesc></ErrorDesc>
	</rec>
</root>



<!-- ECHO REQUEST --> 
<root>
	<rec>
		<Echo>ECHO</Echo>
	</rec>
</root>


<!-- ECHO RESPONSE --> 
<root>
	<rec>
		<Echo>ECHO RECEIVED</Echo>
	</rec>
</root>
================
{
      "referenceNumber": "CARDS_REF_676",
      "country": "UG",
      "unit": "SYB-UG",
      "transaction": {
        "messageDirection": "O",
        "amount": "23522.000",
        "currency": "UGX",
        "transactionType": "DOM",
        "productType": "LCY",
        "product": "Cheque",
        "details": [
          {
            "type": "C",
            "name": null,
            "address": null,
            "accountNumber": "24555",
            "country": null,
            "passportOrOtherIdentity": null,
            "bicOrSortCode": null,
            "freeText": null,
            "vesselName": null
          },
          {
            "type": "B",
            "name": "SCB bank1504",
            "address": null,
            "accountNumber": null,
            "country": "IR",
            "passportOrOtherIdentity": null,
            "bicOrSortCode": null,
            "freeText": null,
            "vesselName": null
          },
          {
            "type": "O",
            "name": null,
            "address": null,
            "accountNumber": null,
            "country": null,
            "passportOrOtherIdentity": null,
            "bicOrSortCode": null,
            "freeText": "12312",
            "vesselName": null
          },
          {
            "type": "P",
            "name": "MUKULU JAMIL",
            "address": null,
            "accountNumber": null,
            "country": "IR",
            "passportOrOtherIdentity": null,
            "bicOrSortCode": null,
            "freeText": null,
            "vesselName": null
          },
          {
            "type": "P",
            "name": "MACHANGA LTD",
            "address": null,
            "accountNumber": null,
            "country": "IR",
            "passportOrOtherIdentity": null,
            "bicOrSortCode": null,
            "freeText": null,
            "vesselName": null
          }
        ]
      }
    }
