# DEPRECATED - TappyUSB Classic Models not sold anymore - refer to https://github.com/TapTrack/TappyTcmpJs for current supported SDK

Driver for working with a TapTrack TappyUSB device that uses the Tappy Classic USB communication protocol
using chrome.serial

## Installation
NPM
```
    npm install @taptrack/tappy-classic
```

Bower
```
    bower install tappy-classic
```

## Detecting Tappies
If you wish, you can manually enter the path to the serial port, but in general, the Tappy
autodetector is more convenient.

```javascript
    var autodetector = new TappyClassic.Autodetector();
    autodetector.setCallback(function(device) {
        // device is an object identical to what
        // chrome.serial.getDevices() passes to its
        // callback
        console.log(device);
    });
    autodetector.setStatusCallback(function(isScanning) {
        if(isScanning) {
            console.log("Scanning for Tappies");
        }
        else {
            console.log("Not scanning");
        }
    });
    autodetector.startScan();
```

## Connecting to Tappies
Once you have determined the path to your Tappy's serial port via auto-detection or another
means, you must connect to it.

```javascript
    var path = "/dev/ttyUSB1"; // windows COM ports also supported

    // create Tappy object with verbose logging if you want detailed output
    // of its operations, if no params are passed, defaults to false
    var tappy = new TappyClassic(path,{verboseLogging:true});
    tappy.connect(function() {
        console.log("Connected");

        // disconnectAsap should be used instead of disconnect
        // as disconnect will throw if the tappy is not connected
        // and disconnectAsap handles the possibility of being called
        // while the tappy is in the process of connecting
        tappy.disconnectAsap();
    });
```

## Sending Commands
While it's possible to send raw commands via safeSendCommand(), you should generally use
the command-specific convenience functions which will handle composing the commands 
and parsing responses.

The convenience functions all have the same basic signature: first the parameters (if relevant), then 
three callbacks - a success callback, an error callback, and an ACK callback. The success callback is
passed parameters that differ based on the exact command being executed. The error callback is passed two
parameters: the first is which of the TappyClassic.ErrorTypes the callback corresponds to, while the second 
parameter contains further data about the error, which can vary depending on the error that occured. The third
callback is called when the Tappy responds with an ACKnowledgement. Note that in some circumstances, the success 
callback is also called when an ACK is received, primarily for commands that do not return any data, such as
storing information in a content slot.

```javascript
    // scan for a tag indefinitely
    // with type-2 enumeration enabled
    tappy.readTagUid(0x00,true,
        function(tagType,tagCode) {
            console.log(tagCode); // Uint8Array
            console.log(TappyClassic.Utils.resolveTagTypeDescription(tagType));
        },
        function(errorType,errorData) {
            console.log(errorType);
            console.log(errorData);
        },
        function() {
            console.log("ACK received");
        });
```
