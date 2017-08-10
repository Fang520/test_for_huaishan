#include <stdio.h>
#include "api_speech_recognizer.h"

int api_speech_recognizer(char* buf, int len, recognizer_cb_t cb)
{
/*
POST
/v20160207/events
{u'content-type': u'multipart/form-data; boundary=simple-avs-message-boundary', u'authorization': u'Bearer Atza|IwEBICktMztSn_4c3RQhgd-ZnRkGTYYsMNrPgyHdqDy4C9Aus3tVZwSlIUbGnuN-fJEu5LSTi5vgiaAw43WhW8ynPDH3cH4i3T5lNBqsV7tlooCKhjvPlj_rm9F5Zoc0x7UvMC9tcgmLKH7OI5vIJ5nDC59VlarDhATMeORNy5s1q2TPDGSdrzZhRhtfspql4wboIja_fen-_Hd4ZUinINyzzWTQeK13yAVcpn7LQc5hstmn2FUqv-dlZvy9qdQmw7Zy1YHFNV52olO797wUwvRM_JWc1dEMepxsLJZEpsoGSK6qakEr0tRLC9yI2jUZsA-Sf46an5etNFO99xxk5DXot3aZAd4m9pqzRKePKI4QWLlQVhYR9d2diJBCKAJV8nRYMutUYjiAJ2TBkKfjcfuqe242JgXLSp8Xjpe51todilI2dJ575hZpB1_pEQbvzawOeMVP_v5XXROFNqaNTWH0JcV39SsJrmIfaejZ5bvWEtv_SLI-oJXUnpXHHcDfo3MqMkz71rdRLhx2yGax1zbeKHWT_130z30X5X5YaE5g9FY15w'}
--simple-avs-message-boundary
Content-Disposition: form-data; name="metadata"
Content-Type: application/json; charset=UTF-8

{"event": {"header": {"dialogRequestId": "avs-dialog-id-1497534590-1", "namespace": "SpeechRecognizer", "name": "Recognize", "messageId": "avs-message-id-1497534590-2"}, "payload": {"profile": "NEAR_FIELD", "format": "AUDIO_L16_RATE_16000_CHANNELS_1"}}, "context": [{"header": {"namespace": "Alerts", "name": "AlertsState"}, "payload": {"allAlerts": [], "activeAlerts": []}}, {"header": {"namespace": "Speaker", "name": "SpeakerState"}, "payload": {"volume": 50, "muted": false}}]}
--simple-avs-message-boundary
Content-Disposition: form-data; name="audio"
Content-Type: application/octet-stream

data

*/
	return 0;
}

