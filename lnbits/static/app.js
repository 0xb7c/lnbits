/** @format */

const user = window.user
const user_wallets = window.user_wallets
const wallet = window.wallet
const transactions = window.transactions

var thehash = ''
var theinvoice = ''
var outamount = ''
var outmemo = ''

// API CALLS

function postAjax(url, data, thekey, success) {
  var params =
    typeof data == 'string'
      ? data
      : Object.keys(data)
          .map(function(k) {
            return encodeURIComponent(k) + '=' + encodeURIComponent(data[k])
          })
          .join('&')
  var xhr = window.XMLHttpRequest
    ? new XMLHttpRequest()
    : new ActiveXObject('Microsoft.XMLHTTP')
  xhr.open('POST', url)
  xhr.onreadystatechange = function() {
    if (xhr.readyState > 3 && xhr.status == 200) {
      success(xhr.responseText)
    }
  }
  xhr.setRequestHeader('Grpc-Metadata-macaroon', thekey)
  xhr.setRequestHeader('Content-Type', 'application/json')
  xhr.send(params)
  return xhr
}

function getAjax(url, thekey, success) {
  var xhr = window.XMLHttpRequest
    ? new XMLHttpRequest()
    : new ActiveXObject('Microsoft.XMLHTTP')
  xhr.open('GET', url, true)
  xhr.onreadystatechange = function() {
    if (xhr.readyState > 3 && xhr.status == 200) {
      success(xhr.responseText)
    }
  }
  xhr.setRequestHeader('Grpc-Metadata-macaroon', thekey)
  xhr.setRequestHeader('Content-Type', 'application/json')
  
  xhr.send()
  return xhr
}



function sendfundsinput() {
  document.getElementById('sendfunds').innerHTML =
    "<div class='modal fade sends' tabindex='-1' role='dialog' aria-labelledby='myLargeModalLabel' aria-hidden='true'>"+
    "<div class='modal-dialog' style='background:#fff;'>"+
    "<div id='sendfunds2' style='padding: 0 10px 0 10px;'><div class='modal-content'>"+
    "<br/><br/>" +
    "<textarea id='pasteinvoice' class='form-control' rows='3' placeholder='Paste an invoice'></textarea></div>" +
    "<div class='modal-footer'>"+
    "<button type='submit' onclick='sendfundspaste()' class='btn btn-primary'>" +
    "Submit</button><button style='margin-left:20px;' type='submit' class='btn btn-primary' onclick='scanQRsend()'>" +
    'Use camera to scan an invoice</button></div>'+
    "</div></div>"
  document.getElementById('receive').innerHTML = ''
}

function sendfundspaste() {
  invoice = document.getElementById('pasteinvoice').value
  theinvoice = decode(invoice)
  outmemo = theinvoice.data.tags[1].value
  outamount = Number(theinvoice.human_readable_part.amount) / 1000
  if (outamount > Number(wallet.balance)) {
    document.getElementById('sendfunds2').innerHTML =
      "<div class='modal-content'>"+
      "<h3><b style='color:red;'>Not enough funds!</b></h3></div>" +
      "<div class='modal-footer'>"+
      "<button style='margin-left:20px;' type='submit' class='btn btn-primary' onclick='cancelsend()'>Continue</button></div>"

  } else {
    document.getElementById('sendfunds2').innerHTML =
      "<div class='modal-content'>"+
      '<h3><b>Invoice details</b></br/>Amount: ' +
      outamount +
      '<br/>Memo: ' +
      outmemo +
      '</h3>' +
      "<div class='input-group input-group-sm'><input type='text' id='invoiceinput' class='form-control' value='" + 
      invoice + 
      "'><span class='input-group-btn'><button class='btn btn-info btn-flat' type='button' onclick='copyfunc()'>Copy</button></span></div></br/></div>" +
      "<div class='modal-footer'>"+     
      "<button type='submit' class='btn btn-primary' onclick='sendfunds(" +
      JSON.stringify(invoice) +
      ")'>Send funds</button>" +
      "<button style='margin-left:20px;' type='submit' class='btn btn-primary' onclick='cancelsend()'>Cancel payment</button>" +
      '</br/></br/></div></div></div>'
  }
}

function receive() {
  document.getElementById('receive').innerHTML =
    "<div class='modal fade receives' tabindex='-1' role='dialog' aria-labelledby='myLargeModalLabel' aria-hidden='true'>"+
    "<div class='modal-dialog' style='background:#fff;'><div id='QRCODE'><div class='modal-content' style='padding: 0 10px 0 10px;'>"+
    "<br/><center><input  style='width:80%' type='number' class='form-control' id='amount' placeholder='Amount' max='1000000' required>" +
    "<input  style='width:80%' type='text' class='form-control' id='memo' placeholder='Memo' required></center></div>" +
    "<div class='modal-footer'>"+  
    "<input type='button' id='getinvoice' onclick='received()' class='btn btn-primary' value='Create invoice' />" +
    '</div></div><br/>'+
    "</div></div></div>"

  document.getElementById('sendfunds').innerHTML = ''
}

function received() {
  memo = document.getElementById('memo').value
  amount = document.getElementById('amount').value
  postAjax(
    '/v1/invoices',
    JSON.stringify({value: amount, memo: memo}),
    wallet.inkey,
    function(data) {
      theinvoice = JSON.parse(data).pay_req
      thehash = JSON.parse(data).payment_hash
      document.getElementById('QRCODE').innerHTML =
        "<div class='modal-content' style='padding: 10px 10px 0 10px;'>"+
        "<center><a href='lightning:" +
        theinvoice +
        "'><div id='qrcode'></div></a>" +
        "<p style='word-wrap: break-word;'>" +
        theinvoice +
        '</p></center>'

      new QRCode(document.getElementById('qrcode'), {
        text: theinvoice,
        width: 300,
        height: 300,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.M
      })


      setInterval(function(){ 
      getAjax('/v1/invoice/' + thehash, wallet.inkey, function(datab) {
        console.log(JSON.parse(datab).PAID)
        if (JSON.parse(datab).PAID == 'TRUE') {
          window.location.href = 'wallet?wal=' + wallet.id + '&usr=' + user
        }
      })}, 3000);

      
    }
  )
}

function cancelsend() {
  window.location.href = 'wallet?wal=' + wallet.id + '&usr=' + user
}

function processing() {
  document.getElementById('processing').innerHTML =
  "<div class='modal fade proc' tabindex='-1' role='dialog' aria-labelledby='myLargeModalLabel' aria-hidden='true'>"+
  "<div class='modal-dialog' style='background:#fff;'>"+
  "<div style='padding: 0 10px 0 10px;'><div class='modal-content'>"+
  "<h3><b>Processing...</b></br/></br/></br/></h3></div>"+
  "</div></div></div>"

  
  window.top.location.href = "lnurlwallet?lightning=" + getQueryVariable("lightning");
}


function getQueryVariable(variable)
{
       var query = window.location.search.substring(1);
       var vars = query.split("&");
       for (var i=0;i<vars.length;i++) {
               var pair = vars[i].split("=");
               if(pair[0] == variable){return pair[1];}
       }
       return(false);
}

function sendfunds(invoice) {

  document.getElementById('sendfunds2').innerHTML =
  "<div class='modal-content'></br/></br/>"+
  '<h3><b>Processing...</b></h3><</br/></br/></br/></div> ';

  postAjax(
    '/v1/channels/transactions',
    JSON.stringify({payment_request: invoice}),
    wallet.adminkey,

    function(data) {
      thehash = JSON.parse(data).payment_hash

      setInterval(function(){ 
        getAjax('/v1/payment/' + thehash, wallet.adminkey, function(datab) {
        console.log(JSON.parse(datab).PAID)
        if (JSON.parse(datab).PAID == 'TRUE') {
          window.location.href = 'wallet?wal=' + wallet.id + '&usr=' + user
        }
      })}, 3000);

    }
  )

}

function scanQRsend() {
  document.getElementById('sendfunds2').innerHTML =
    "<div class='modal-content'>"+
    "<br/><div id='loadingMessage'>🎥 Unable to access video stream (please make sure you have a webcam enabled)</div>" +
    "<canvas id='canvas' hidden></canvas><div id='output' hidden><div id='outputMessage'></div>" +
    "<br/><span id='outputData'></span></div></div><div class='modal-footer'>"+  
    "<button type='submit' class='btn btn-primary' onclick='cancelsend()'>Cancel</button><br/><br/>"
  var video = document.createElement('video')
  var canvasElement = document.getElementById('canvas')
  var canvas = canvasElement.getContext('2d')
  var loadingMessage = document.getElementById('loadingMessage')
  var outputContainer = document.getElementById('output')
  var outputMessage = document.getElementById('outputMessage')
  var outputData = document.getElementById('outputData')

  // Use facingMode: environment to attemt to get the front camera on phones
  navigator.mediaDevices
    .getUserMedia({video: {facingMode: 'environment'}})
    .then(function(stream) {
      video.srcObject = stream
      video.setAttribute('playsinline', true) // required to tell iOS safari we don't want fullscreen
      video.play()
      requestAnimationFrame(tick)
    })

   function tick() {
    loadingMessage.innerText = '⌛ Loading video...'
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      loadingMessage.hidden = true
      canvasElement.hidden = false
      outputContainer.hidden = false
      canvasElement.height = video.videoHeight
      canvasElement.width = video.videoWidth
      canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height)
      var imageData = canvas.getImageData(
        0,
        0,
        canvasElement.width,
        canvasElement.height
      )
      var code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert'
      })
      if (code) {

        outputMessage.hidden = true
        outputData.parentElement.hidden = false
        outputData.innerText = JSON.stringify(code.data)
        outstr = ""
        outmemo = ""
        if (code.data.split(":")[0] == "lightning") {
          theinvoice = decode(code.data.split(":")[1])
          outmemo = theinvoice.data.tags[1].value
          outstr = JSON.stringify(code.data.split(":")[1])
        }
        
        if (code.data.substring(0, 4).toUpperCase() != "LNBC"){
          document.getElementById('sendfunds2').innerHTML =
            "<div class='row'><div class='col-md-6'>" +
            "<h3><b style='color:red;'>Not a lightning invoice</b></h3>" +
            "<button style='margin-left:20px;' type='submit' class='btn btn-primary' onclick='cancelsend()'>Continue</button>" +
            '</br/></br/></div></div>'
        }
        else{
          
          theinvoice = decode(code.data)
          outmemo = theinvoice.data.tags[1].value
          outstr = JSON.stringify(code.data)
        }


        outamount = Number(theinvoice.human_readable_part.amount) / 1000
        if (outamount > Number(wallet.balance)) {
          document.getElementById('sendfunds2').innerHTML =
            "<div class='row'><div class='col-md-6'>" +
            "<h3><b style='color:red;'>Not enough funds!</b></h3>" +
            "<button style='margin-left:20px;' type='submit' class='btn btn-primary' onclick='cancelsend()'>Continue</button>" +
            '</br/></br/></div></div>'
        } else {
          document.getElementById('sendfunds2').innerHTML =
            "<div class='row'><div class='col-md-6'>" +
            '<h3><b>Invoice details</b></br/>Amount: ' +
            outamount +
            '<br/>Memo: ' +
            outmemo +
            '</h3>' +
            "<div class='input-group input-group-sm'><input type='text' id='invoiceinput' class='form-control' value='" + 
             outstr +
             "'><span class='input-group-btn'><button class='btn btn-info btn-flat' type='button' onclick='copyfunc()'>Copy</button></span></div></br/>" +
            "<button type='submit' class='btn btn-primary' onclick='sendfunds(" +
            outstr +
            ")'>Send funds</button>" +
            "<button style='margin-left:20px;' type='submit' class='btn btn-primary' onclick='cancelsend()'>Cancel payment</button>" +
            '</br/></br/></div></div>'
        }
      } else {
        outputMessage.hidden = false
        outputData.parentElement.hidden = true
      }
    }
    requestAnimationFrame(tick)
  }
}



function copyfunc(){
  var copyText = document.getElementById("invoiceinput");
  copyText.select();
  copyText.setSelectionRange(0, 99999); 
  document.execCommand("copy");

}

function deletewallet() {
  var url = 'deletewallet?wal=' + wallet.id + '&usr=' + user
  window.location.href = url
}

function sidebarmake() {
  document.getElementById('sidebarmake').innerHTML =
    "<li><div class='form-group'>" +
    "<input  style='width:70%;float:left;' type='text' class='form-control' id='walname' placeholder='Name wallet' required>" +
    "<button style='width:30%;float:left;' type='button' class='btn btn-primary' onclick='newwallet()'>Submit</button>" +
    '</div></li><br/><br/>'
}

function newwallet() {
  var walname = document.getElementById('walname').value
  window.location.href =
    'wallet?' + (user ? 'usr=' + user + '&' : '') + 'nme=' + walname
}

function drawChart(transactions) {
  var linechart = []
  var transactionsHTML = ''
  var balance = 0

  for (var i = 0; i < transactions.length; i++) {
    var tx = transactions[i]
    var datime = convertTimestamp(tx.time)

    // make the transactions table
    transactionsHTML =
      "<tr><td  style='width: 50%'>" +
      tx.memo +
      '</td><td>' +
      datime +
      '</td><td>' +
      parseFloat(tx.amount / 1000) +
      '</td></tr>' +
      transactionsHTML

    // make the line chart
    balance += parseInt(tx.amount / 1000)
    linechart.push({y: datime, balance: balance})
  }

  document.getElementById('transactions').innerHTML = transactionsHTML

  if (linechart[0] != '') {
    document.getElementById('satschart').innerHTML =
      "<div class='row'><div class='col-md-6'><div class='box box-info'><div class='box-header'>" +
      "<h3 class='box-title'>Spending</h3></div><div class='box-body chart-responsive'>" +
      "<div class='chart' id='line-chart' style='height: 300px;'></div></div></div></div></div>"
  }

  console.log(linechart)
  var line = new Morris.Line({
    element: 'line-chart',
    resize: true,
    data: linechart,
    xkey: 'y',
    ykeys: ['balance'],
    labels: ['balance'],
    lineColors: ['#3c8dbc'],
    hideHover: 'auto'
  })
}

function convertTimestamp(timestamp) {
  var d = new Date(timestamp * 1000),
    yyyy = d.getFullYear(),
    mm = ('0' + (d.getMonth() + 1)).slice(-2),
    dd = ('0' + d.getDate()).slice(-2),
    hh = d.getHours(),
    h = hh,
    min = ('0' + d.getMinutes()).slice(-2),
    ampm = 'AM',
    time
  time = yyyy + '-' + mm + '-' + dd + ' ' + h + ':' + min
  return time
}

if (transactions.length) {
  drawChart(transactions)
}

if (wallet) {
  postAjax('/v1/checkpending', '', wallet.adminkey, function(data) {})
}
