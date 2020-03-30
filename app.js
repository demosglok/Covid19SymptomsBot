/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
//  https = require('https'),
  request = require('request');

const app = express();
app.set('port', process.env.PORT || 9003);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));


const admin = require("firebase-admin");

const serviceAccount = require("./config/firebase.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://covid19symptomsbot.firebaseio.com"
});
const db = admin.firestore();
const peopleDB = db.collection('people');
const answersDB = db.collection('answers');

const questions = require('./questions');
let currentQuestionsState = {};

/*
 * Be sure to setup your config values before running this code. You can
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s",
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);
    processAnswer(senderID, quickReplyPayload);

    return;
  } else if(metadata == 'QUESTION_CITY') {
    addQuestionAnswerToLocalStore(senderID, messageText);
    stopQuestionsIfNoMore(senderID);
    sendTextMessage(senderID, "Thank you for answering. This is important. See you tomorrow.");
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText.replace(/[^\w\s]/gi, '').trim().toLowerCase()) {
      case 'hello':
      case 'hi':
        createUser(senderID);
        sendHiMessage(senderID);
        askForAgreement(senderID);
        break;
      case 'stop':
        updateUser(senderID, {agree: false});
        sendTextMessage(senderID, "Thanks for interest in bot. Once you're ready to start be questioned again, just type 'hi'");
        break;
      case "askme": 
        questionUser(senderID);
        break;
      case 'receipt':
        requiresServerURL(sendReceiptMessage, [senderID]);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;

      case 'read receipt':
        sendReadReceipt(senderID);
        break;



      default:
        sendTextMessage(senderID, messageText);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
  }
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

function createUser(id) {
  const doc = peopleDB.doc(id);
  doc.get().then(foundDocument => {
    if(!foundDocument.exist) {
      doc.set({last_question_time: 0}).catch(err => console.log('error setting', err.message));
    }
  }).catch(err => console.log(`error querying document ${id}`, err.message));
}
function updateUser(id, updateData) {
  const doc = peopleDB.doc(id);
  doc.get().then(foundDocument => {
    if(foundDocument.exist) {
      doc.update(updateData).catch(err => console.log('error updating', err.message));
    }
  }).catch(err => console.log(`error querying document ${id}`, err.message));
}

function sendHiMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: `
hello, I’m covid19 symptoms bot. My aim is to help scientist and researches get better picture of untested and invisible covid19 cases. \n
I will ask 7 simple questions every day if you agree to have this info collected. It’ll take less then 2 minutes for you but will help a lot 
in global scale. None of your personal information will be shared. Only anonymised  and aggregated data will be available to verified 
researchers.\n You can check my source code here https://github.com/demosglok/Covid19SymptomsBot. \n
You can get more info on this page. https://covid19symptoms.online/info.html \n
Why it is important ttps://covid19symptoms.online/important.html\n
You can stop regular questions at any time. \n\n
Possible commands for bot are \n"hi" - this message, \n"askme" - ask set of questions,
"stop" - to stop regular asking, \n"deleteme" - delete all my data forever
      `
    }
  }

  callSendAPI(messageData);
}

function askForAgreement(recipientId)  {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Do you agree to be questioned regularly? (you can cancel any time)",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Yes",
          "payload":"AGREE_TO_BE_QUESTIONED"
        },
        {
          "content_type":"text",
          "title":"No",
          "payload":"DISAGREE_TO_BE_QUESTIONED"
        },
      ]
    }
  };

  callSendAPI(messageData);

}
function processAnswer(senderID, quickReplyPayload) {
  switch(quickReplyPayload) {
    case 'AGREE_TO_BE_QUESTIONED':
      updateUser(senderID, {agree: true});
      questionUser(senderID);
      break;
    case 'DISAGREE_TO_BE_QUESTIONED':
      updateUser(senderID, {agree: false});
      sendTextMessage(senderID, 'Thanks for interest in this BOT and COVID19 response. If you change your mind, the bot is always happy and start questioning');
      break;
    case 'START_QUESTIONING_OK':
      currentQuestionsState[senderID] = {step: 0, answers: {}};
      askHealthQuestion(senderID);
      break;
    case 'QUESTIONING_NOTHING_CHANGE':
      updateUser(senderID, {last_question_time: parseInt(Date.now() / 1000)})
      break;
    case 'QUESTIONING_SKIP_TODAY':
      updateUser(senderID, {last_question_time: parseInt(Date.now() / 1000)})
      break;
    case 'HEALTH_ANSWER_YES':
      addQuestionAnswerToLocalStore(senderID, 'yes');
      if(currentQuestionsState[senderID].step < questions.length) {
        askHealthQuestion(senderID);
      } else {
        stopQuestionsIfNoMore(senderID);
        sendTextMessage(senderID, "Thank you for answering. This is important. See you tomorrow.");
      }
      break;
    case 'HEALTH_ANSWER_NO':
      addQuestionAnswerToLocalStore(senderID, 'no');
      if(currentQuestionsState[senderID].step < questions.length) {
        askHealthQuestion(senderID);
      } else {
        stopQuestionsIfNoMore(senderID);
        sendTextMessage(senderID, "Thank you for answering. This is important. See you tomorrow.");
      }
      break;
    case 'HEALTH_ANSWER_NOT_SURE':
      addQuestionAnswerToLocalStore(senderID, 'not sure');
      if(currentQuestionsState[senderID].step < questions.length) {
        askHealthQuestion(senderID);
      } else {
        stopQuestionsIfNoMore(senderID);
        sendTextMessage(senderID, "Thank you for answering. This is important. See you tomorrow.");
      }
      break;
  }
}

function askHealthQuestion(recipientId) {
  const step = currentQuestionsState[recipientId].step;
  if(step != undefined && questions[step]) {
    const question = questions[step];
    const messageData = {
      recipient: {
        id: recipientId
      },
      message: {
        text: question.text,
      }
    };

    if(question.fieldname == 'city') {
      messageData.message.metadata = "QUESTION_CITY";
    } else {
      messageData.message.quick_replies = [
        {"content_type":"text", "title":"YES","payload":"HEALTH_ANSWER_YES"},
        {"content_type":"text", "title":"NO","payload":"HEALTH_ANSWER_NO"},
        {"content_type":"text", "title":"Not sure","payload":"HEALTH_ANSWER_NOT_SURE"},
      ];      
    }

    callSendAPI(messageData);
  }
}
function addQuestionAnswerToLocalStore(recipientId, answer) {
  const step = currentQuestionsState[recipientId].step;
  if(step != undefined && questions[step]) {
    const question = questions[step];
    currentQuestionsState[recipientId].answers[question.fieldname] = answer;
    currentQuestionsState[recipientId].step++;
  }
}
function stopQuestionsIfNoMore(recipientId) {
  const step = currentQuestionsState[recipientId].step;
  if(step != undefined && questions[step]) {
    const answers = currentQuestionsState[recipientId].answers;
    answersDB.doc(recipientId).set({...answers, timestamp: parseInt(Date.now() / 1000)}).catch(err => console.log('err saving answers', err.message));
    updateUser(senderID, {last_question_time: parseInt(Date.now() / 1000)});
    delete currentQuestionsState[recipientId];
  }
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

function askToStartQuestioning(recipientId, keepPreviousOption) {
  const text = keepPreviousOption 
        ? "Hello, I'll ask 7 questions about your health now. If nothing changed, select 'Nothing change', otherwise press OK"
        : "Hello, I'll ask 7 questions about your health now. If you want to skip, select 'Skip today', otherwise press OK";
  const quick_replies = [{"content_type":"text", "title":"OK","payload":"START_QUESTIONING_OK"}];
  if(keepPreviousOption) {
    quick_replies.push({"content_type":"text", "title":"Nothing change","payload":"QUESTIONING_NOTHING_CHAGE"});
  } else {
    quick_replies.push({"content_type":"text", "title":"Skip today","payload":"QUESTIONING_SKIP_TODAY"});
  }
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text,
      quick_replies
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Do you feel good?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Yes",
          "payload":"ANSWER_YES"
        },
        {
          "content_type":"text",
          "title":"No",
          "payload":"ANSWER_NO"
        },
        {
          "content_type":"text",
          "title":"Not sure",
          "payload":"ANSWER_NOT_SURE"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}



/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

function questionUser(userID) {
  answersDB.doc(userId).get().then(doc => {
    const keepPreviousOption = doc.exists;
    askToStartQuestioning(userID, keepPreviousOption);
  }).catch(err => console.log('error querying answer for', userID, err.message));
}
setTimeout(() => {
  peopleDB.where('last_question_time', '<', Date.now()/1000-24*60*60).get()
	  .then((snapshot) => {
	    snapshot.forEach((doc) => {
        askToStartQuestioning(userID, true);
	    });
	  })
	  .catch(err => console.log('db error', err.message));
    //sendTextMessage('2782936258454619', 'delayed message');
}, 3000000000);
// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
