(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD
        define(['ndef'], factory);
    } else if (typeof exports === 'object') {
        // Node, CommonJS-like
        var ndef = null;
        try {
            ndef = require('@taptrack/ndef');
        }
        catch (e1) {
            ndef = require('ndef');
        }
        module.exports = factory(ndef);
    } else {
        // Browser globals (root is window)
        root.TappyClassic = factory(root.Ndef);
    }
}(this, function (Ndef) {
    /**
     * Utility functions for Tappy operations and debugging
     *
     * @version 1.0.2
     */

    var TappyUtils = function () {
        throw "Do not instantiate TappyUtils";
    };

    /**
     * Converts a byte array into a hexadecimal
     * string representation
     *
     * @param {Uint8Array} data binary data
     * @return {string} Hexadecimal represenation of data
     */
    TappyUtils.bytesToHexString = function(data) {
        var hexString = "";
        for(var x = 0; x < data.length; x++) {
            var hexValue = data[x].toString(16).toUpperCase();
            if(data[x] <= 15) {
                // gives zero padding to hex values less than 16
                hexString = hexString.concat("0" + hexValue);
            }
            else {
                hexString = hexString.concat(hexValue);
            }
        }
        return hexString;
    };

    /**
     * Converts a byte array into a string
     *
     * @param {Uint8Array} data binary data
     * @return {string} string
     */
    TappyUtils.bytesToString = function(arr) {
        var binstr = Array.prototype.map.call(arr, function (ch) {
            return String.fromCharCode(ch);
        }).join('');

        var escstr = binstr.replace(/(.)/g, function (m, p) {
            var code = p.charCodeAt(0).toString(16).toUpperCase();
            if (code.length < 2) {
                code = '0' + code;
            }
            return '%' + code;
        });
        return decodeURIComponent(escstr);    
    };

    /**
     * Converts a string into a binary array representation
     *
     * @param {string} string to convert
     * @return {Uint8Array}
     */
    TappyUtils.stringToUint8Array = function(string) {
        var escstr = encodeURIComponent(string);
        var binstr = escstr.replace(/%([0-9A-F]{2})/g, function(match, p1) {
            return String.fromCharCode('0x' + p1);
        });
        var ua = new Uint8Array(binstr.length);
        Array.prototype.forEach.call(binstr, function (ch, i) {
            ua[i] = ch.charCodeAt(0);
        });
        return ua;
    };

    /**
     * Resolve a standard Tappy tag type byte to a human-readable
     * English description
     *
     * @param {integer} tagType single byte tag type
     * @return {string} human-readable English tag description
     */
    TappyUtils.resolveTagTypeDescription = function(tagType) {
        var tagName = "Unknown";
        switch(tagType) {
            case 0:
                tagName = "Unknown Tag";
                break;
            case 1:
                tagName = "Mifare Ultralight";
                break;
            case 2:
                tagName = "NTAG 203";
                break;
            case 3:
                tagName = "Mifare Ultralight C";
                break;
            case 4:
                tagName = "Mifare Classic Standard - 1k";
                break;
            case 5:
                tagName = "Mifare Classic Standard - 4k";
                break;
            case 6:
                tagName = "Mifare DESFire EV1 2k";
                break;
            case 7:
                tagName = "Generic NFC Forum Type 2 tag";
                break;
            case 8:
                tagName = "Mifare Plus 2k CL2";
                break;
            case 9:
                tagName = "Mifare Plus 4k CL2";
                break;
            case 10:
                tagName = "Mifare Mini";
                break;
            case 11:
                tagName = "Generic NFC Forum Type 4 tag";
                break;
            case 12:
                tagName = "Mifare DESFire EV1 4k";
                break;
            case 13:
                tagName = "Mifare DESFire EV1 8k";
                break;
            case 14:
                tagName = "Mifare DESFire - Unspecified model and capacity";
                break;
            case 15:
                tagName = "Topaz 512";
                break;
            case 16:
                tagName = "NTAG 210";
                break;
            case 17:
                tagName = "NTAG 212";
                break;
            case 18:
                tagName = "NTAG 213";
                break;
            case 19:
                tagName = "NTAG 215";
                break;
            case 20:
                tagName = "NTAG 216";
                break;
        }
        return tagName;
    };
    /**
     * Tappy Main Communication Code
     * @version 1.0.2
     * /


    /**
     * Full set of callbacks used by the tappy
     *
     * @constructor
     * @this {TappyCallbacks}
     */
    var TappyCallbacks = function() {
        /**
         * Fired when an ACK is received
         */
        this.ackResponseCb = null;
        /**
         * Fired when a NACK is received
         */
        this.nackResponseCb = null;
        /**
         * Fired when an LCS error is encountered on an inbound frame
         *
         * @param {Uint8Array} buffer the state of the buffer starting
         * at the start of instruction where the bad LCS was encountered
         */
        this.lcsErrorResponseCb = null;
        /**
         * Fired when a DCS error is encountered on an inbound frame
         *
         * @param {Uint8Array} frame the frame with the bad DCS
         */
        this.dcsErrorResponseCb = null;
        /**
         * Chrome serial port had an error on send
         *
         * @param {sendInfo} sendInfo the info that the chrome serial driver
         * responded with
         * @param {ArrayBuffer} data that was being sent
         */
        this.serialPortErrorCb = null;
        /**
         * A valid response frame was detected
         *
         * @param {Uint8Array} frame the frame extracted
         */
        this.validResponseFrameCb = null;
    };

    /**
     * Options for configuring how a Tappy will behave
     *
     * @constructor
     * @this {TappyConfigParams}
     */
    var TappyConfigParams = function() {
        /**
         * Setting verbose logging to true will cause the driver
         * to send a large amount of data to console.log in order
         * to track its operations
         */
        this.verboseLogging = false;

        /**
         * The postample is a set of bytes appended to packets
         * before sending. This helps with some issues where a receive 
         * or send buffer is not completely flushed.
         * 
         * This parameter controls the number of postamble characters.
         * By default, two 0x00s are appended to every packet.
         */
        this.postambleLength = 2;

        /**
         * The preamble is a set of bytes prepended to packets
         * before sending. This helps with some issues where a receive 
         * or send buffer is not completely flushed.
         * 
         * This parameter controls the number of preamble characters.
         * By default, two 0x00s are prepended to every packet.
         */
        this.preambleLength = 2;

        /**
         * This parameter controls the way the driver will handle
         * LCS errors. Valid options are:
         *
         * Tappy.EMPTY_BUFFER_ON_LCS_ERR: Empty the whole buffer
         * Tappy.REMOVE_ONLY_BAD_START_ON_LCS_ERR: Only remove the 
         * start of message, l1, l2, and lcs bytes
         *
         * Note that, in practise, the difference between these two
         * strategies may be minimal as it is dependent on how large
         * the chunks sent by the serial port are. If a single byte is 
         * sent at a time, the two strategies will do exactly the same 
         * thing.
         */
        this.lcsErrorStrategy = Tappy.EMPTY_BUFFER_ON_LCS_ERR;

        /**
         * This parameter controls how long the driver will wait for
         * an ack after sending the stop command before timing out
         */
        this.safeSendWaitTime = 25; 
    };


    /**
     * Creates an instance of a Tappy driver
     *
     * @this {Tappy}
     * @constructor
     * @param {string} path The path to the serial port as returned by
     * chrome.serial.getDevices
     * @param {TappyConfigParams} params optional configuration parameters
     */
    var Tappy = function(path,params) {
        if(typeof path === "undefined" || path === null) {
            throw "Must have a path";
        }

        var defaultOptions = new TappyConfigParams();
        var options = params || {};
        for (var opt in defaultOptions) {
            if (defaultOptions.hasOwnProperty(opt) && !options.hasOwnProperty(opt)) {
                options[opt] = defaultOptions[opt];
            }
        }

        var self = this;

        /**
         * {string} path to the serial port, the format of this string
         * will vary depending on platform. On POSIX systems it will
         * be something like /dev/ttyUSB1 while Windows sytems will
         * have paths like COM1
         */
        this.path = path;

        /**
         * {integer} chrome.serial.connect connection id
         */
        this.connectionId = null;

        /**
         * {boolean} If the Tappy is currently connecting
         */
        this.isConnecting = false;

        /**
         * {boolean} Determines if the callbacks have been attached
         * to the serial port after connecting. 
         * This is analogous to putting the needle on a record, and
         * is managed by connect()
         */
        this.hasAttached = false;

        /**
         * {boolean} This flag is set by disconnectAsap()
         * to inform the connection callback to disconnect
         * immediately upon establishing the connection.
         * This is used to made disconnectAsap still function
         * if it is called while the connection is pending
         */
        this.disconnectImmediately = false;

        /**
         * see TappyConfigParams.postambleLength
         */
        this.postambleLength = options.postambleLength;

        /**
         * see TappyConfigParams.preambleLength
         */
        this.preambleLength = options.preambleLength;

        /**
         * see TappyConfigParams.verboseLogging
         */
        this.verboseLogging = options.verboseLogging;

        /**
         * see TappyConfigParams.lcsErrorStrategy
         */
        this.lcsErrorStrategy = options.lcsErrorStrategy;

        /**
         * see TappyConfigParams.safeSendWaitTime
         */
        this.safeSendWaitTime = options.safeSendWaitTime;

        /**
         * {function} This function is called during a 
         * safeSend after the stop command has been processed
         */
        this.pendingOperation = null;

        /**
         * {Uint8Array} Buffers the incoming bytes from
         * the serial port
         */
        this.bufferedData = new Uint8Array(0);

        /**
         * Standard callback that is attached to the serial port
         */
        this.onReceiveCallback = function(info) {
            var recConnectionId = info.connectionId;
            var newDataBuf = info.data;
            if(self.isConnected() && recConnectionId === self.connectionId) {
                self.log("Data received");
                var newData = new Uint8Array(newDataBuf);
                var updatedBufferedData = new Uint8Array(self.bufferedData.length+newData.length);
                updatedBufferedData.set(self.bufferedData);
                updatedBufferedData.set(newData,self.bufferedData.length);
                self.bufferedData = updatedBufferedData;
                self.log("Buffer status:");
                self.log(self.bufferedData);
                self.scanBufferAndDispatch();
            }
        };

        /**
         * The current set of callbacks for the driver to call
         * see TappyCallbacks
         */
        this.callbacks = new TappyCallbacks();
    };

    // start of instruction, l1, l2, lcs, dcs
    Tappy.FRAME_SIZE_NO_DATA = 6;
    // ack/nack frame size
    Tappy.FRAME_SIZE_N_ACK = 8;

    // bad lcs handling strategies
    // see: TappyConfigParams
    Tappy.EMPTY_BUFFER_ON_LCS_ERR = 0;
    Tappy.REMOVE_ONLY_BAD_START_ON_LCS_ERR = 1;

    // this is the reset instruction
    Tappy.RAW_RESET_INS = new Uint8Array([0x00, 0xFF, 0x00, 0x01, 0xFF, 0x00, 0x00]);
    Tappy.CommandCodes = {
        /**
         * This command soft resets the Tappy including wiping
         * content slots and stopping execution of its current tasks
         */
        RESET: 0x00,
        /**
         * Stop soft resets the Tappy but does not empty
         * conent slots.
         */
        STOP: 0x27
    };

    // this is currently the only standard response code besides ACK/NACK
    Tappy.APPLICATION_ERROR_CODE = 0x7F;

    /**
     * Error types used for the standard
     * callbacks generated by Tappy.generateStandardCallbacks
     */
    Tappy.ErrorTypes = {
        /**
         * The Tappy replied with a NACK
         */
        NACK: 0x01,
        /**
         * LCS error occured on validating inbound frame
         */
        LCS: 0x02,
        /**
         * DCS error occured on validating inbound frame
         */
        DCS: 0x03,
        /**
         * The Tappy responded with a standard application error
         * response frame 
         */
        APPLICATION: 0x04,
        /**
         * A serial port error occured
         */
        SERIAL: 0x05,
        /**
         * An error occured making sense of the response frame.
         * For example, this could be issued if a command that is
         * supposed to return an NDEF message returns bytes that 
         * cannot be parsed as an NDEF message.
         *
         * The Tappy driver itself does not issue errors of this
         * type, but extending commands can use it to provide a
         * consistent way to notify of an invalid response
         */
        BAD_RESPONSE: 0x06 
    };

    /**
     * Internal function
     * Logs to console if verbose logging is on
     *
     * @param {?} objToLog object to pass to console.log
     */
    Tappy.prototype.log = function(objToLog) {
        if(this.verboseLogging) {
            console.log(objToLog);
        }
    };

    /**
     * Connect to the serial port path specified.
     * Will silently not attempt to connect if a connection has already been made
     *
     * @param {callback} cb optional callback to be called when connect completes
     */
    Tappy.prototype.connect = function(cb) {
        if(!this.isConnecting && !this.isConnected()) {
            var self = this;
            this.isConnecting = true;
            self.log("Starting connect");
            // this should probably have a failure state
            // but the chrome docs dont describe what happens
            chrome.serial.connect(
                    this.path,
                    {bitrate: 115200},
                    function(connectionInfo) {
                        self.connectionId = connectionInfo.connectionId;
                        self.log("Connected with connection id "+self.connectionId);
                        self.attachReadWrite();
                        self.isConnecting = false;

                        if(typeof cb === "function") {
                            cb();
                        }

                        if(self.disconnectImmediately) {
                            self.log("Immediate disconnect requested");
                            self.disconnect();
                        }

                    });
        }
    };

    /**
     * Used to let the tappy know to disconnect as soon as it can
     *
     */
    Tappy.prototype.disconnectAsap = function() {
        this.log("Disconnecting as soon as possible");
        this.disconnectImmediately = true;
        if(!this.isConnecting && this.isConnected()) {
            this.disconnect();
        }
    };

    /**
     * Disconnect from the serial port. Note that you should usually use
     * disconnectAsap() instead as this function will throw if you try to
     * disconnect() when already disconnected. Additionally, if you call
     * disconnect() while the connect() process is pending, the tappy will
     * be left in a connected state. 
     *
     * @throws if you try to disconnect while the tappy is still connecting
     */
    Tappy.prototype.disconnect = function() {
        if(this.isConnecting) {
            throw "Connection still in the process of being established";
        }
        if(this.isConnected()) {
            var self = this;
            self.log('Starting to disconnect from connection with id '+this.connectionId);

            // TODO: Make better guards around this
            // In particular, find out what a failed connect means
            // and determine if the connectionId should be set to null
            // before like it is currently or if guards around it should be setup
            // so it can stay set during the duration of the disconnect process
            // but avoid trying to disconnect it while a disconnect is pending
            var cnxn = this.connectionId;
            self.connectionId = null;
            chrome.serial.disconnect(cnxn, function(result) {
                if(result) {
                    self.log('Disconnected');
                }
                else {
                    self.log("Disconnect failed");
                }
            });
        }
    };

    /**
     * Determines if the Tappy is connected or not. Note that it is possible
     * to be connected but have the serial connection be in a read-only state.
     *
     * @return {boolean} Connection status
     */
    Tappy.prototype.isConnected = function() {
        return this.connectionId !== null;
    };

    /**
     * Attach the read/write callback if it hasn't been yet. This operation
     * is performed internally by connect(), but is idempotent.
     */
    Tappy.prototype.attachReadWrite = function() {
        if(!this.hasAttached) {
            this.hasAttached = true;
            chrome.serial.onReceive.addListener(this.onReceiveCallback);
        }
    };

    /**
     * Causes the driver to scan through its buffer and dispatch
     * any messages it finds to the appropriate currently attached callbacks
     */
    Tappy.prototype.scanBufferAndDispatch = function() {
        if(this.bufferedData.length >= Tappy.FRAME_SIZE_NO_DATA) {
            var rescanBuffer = false;
            var chopTo = 0;
            for(var i = 0; i < this.bufferedData.length - 1; i++) {
                if(this.bufferedData[i] === 0x00 && this.bufferedData[i+1] === 0xFF) {
                    var extractResult = Tappy.extractFrame(i,this.bufferedData);
                    if (extractResult.isDcsError) {
                        this.log("Dcs error:");
                        this.log(extractResult.frame);

                        rescanBuffer = true;
                        if(typeof this.callbacks.dcsErrorResponseCb === "function") {
                            this.callbacks.dcsErrorResponseCb(extractResult.frame);
                        }
                        chopTo = extractResult.lastIndex+1;
                    } else if(extractResult.isAck) {
                        this.log("Ack received");

                        rescanBuffer = true;
                        if(typeof this.callbacks.ackResponseCb === "function") {
                            this.callbacks.ackResponseCb();
                        }

                        chopTo = extractResult.lastIndex+1;
                    } else if(extractResult.isNack) {
                        this.log("Nack received");

                        rescanBuffer = true;
                        if(typeof this.callbacks.nackResponseCb === "function") {
                            this.callbacks.nackResponseCb();
                        }

                        chopTo = extractResult.lastIndex+1;
                    } else if(extractResult.isComplete) {
                        this.log("Complete frame received");
                        this.log(extractResult.frame);

                        rescanBuffer = true;
                        if(typeof this.callbacks.validResponseFrameCb === "function") {
                            this.callbacks.validResponseFrameCb(extractResult.frame);
                        }
                        // remove the frame from the buffer
                        chopTo = extractResult.lastIndex+1;
                    } else if(extractResult.isLcsError) {
                        // no way to tell if the in between bytes
                        // are valid or if this is a spurious construct
                        // that happened to appear to be a start of frame
                        //
                        // we have to get this lcs out of the buffer
                        // but given that the 'correct' action is unknown, its configurable
                        // note: both of these options are identical if data is coming in in
                        // single bytes

                        this.log("Lcs error:");
                        this.log(this.bufferedData.slice(i));

                        rescanBuffer = true;
                        if(typeof this.callbacks.lcsErrorResponseCb === "function") {
                            this.callbacks.lcsErrorResponseCb(this.bufferedData.slice(i));
                        }

                        if(this.lcsErrorStrategy === Tappy.EMPTY_BUFFER_ON_LCS_ERR) {
                            chopTo = this.bufferedData.length;
                        } else {
                            chopTo = i+5; // grab the bad lcs
                        }
                    } else {
                        this.log("No full frame found");
                        rescanBuffer = false;
                        // otherwise, we're probably awaiting more bytes
                        // can't differentiate this from invalid
                        // frame boundary due to protocol limitations
                        // so its possible that if the buffer had
                        // 0x00,0xFF,0xFF,0xFF,0x00 in it, we could be
                        // waiting for an extremely long time

                        // remove garbage bytes (probably a preamble)
                        chopTo = (i);
                    }
                    break;
                }
            }

            if(chopTo >= this.bufferedData.length) {
                this.bufferedData = new Uint8Array(0);
            }
            else if(chopTo > 0) {
                this.bufferedData = this.bufferedData.slice(chopTo,this.bufferedData.length);
            }

            // triggers a rescan if a frame was found
            // this handles the case of multiple frames
            // being in the buffer at once
            if(rescanBuffer) {
                this.scanBufferAndDispatch();
            }
        }
    };

    /**
     * Object for a tappy frame scan result
     *
     * @constructor
     * @this {TappyFrameResult}
     */
    var TappyFrameResult = function(frame,lastIndex, lcsError, dcsError, isAck, isNack) {
        /**
         * {Uint8Array} raw frame
         */
        this.frame = frame;

        /**
         * {boolean} whether the frame is complete or not
         */
        this.isComplete = frame !== null;

        /**
         * {boolean} if the frame is an ACK
         */
        this.isAck = isAck;

        /**
         * {boolean} if the frame is an NACK
         */
        this.isNack = isNack;

        /**
         * {boolean} if the frame has an LCS error
         */
        this.isLcsError = lcsError;

        /**
         * {boolean} if the frame has a DCS error
         */
        this.isDcsError = dcsError;

        /**
         * {integer} The last index in the buffer of the frame
         */
        this.lastIndex = lastIndex;
    };

    /**
     * Static function for extracting the first valid frame from a Uint8Array
     *
     * @param {integer} startIndex where to start scanning the array
     * @param {Uint8Array} buffer array to scan
     * @return {TappyFrameResult} results describing the first frame found if there is one
     */
    Tappy.extractFrame = function(startIndex, buffer) {


        if(buffer.length < (startIndex+Tappy.FRAME_SIZE_NO_DATA)) {
            return new TappyFrameResult(null, -1, false, false, false, false);
        }

        // length high
        var lh = buffer[startIndex+2];
        var ll = buffer[startIndex+3];
        var lcs = buffer[startIndex+4];
        var length = lh*256+ll;
        if(((ll + lh + lcs) % 256) !== 0) {
            return new TappyFrameResult(null, -1, true, false, false, false);
        }

        // check for special ack/nack frame
        if(length === 2 && buffer.length >= (startIndex+Tappy.FRAME_SIZE_N_ACK)) {
            if(buffer[startIndex+5] === 0x00 &&
                    buffer[startIndex+6] === 0xFF &&
                    buffer[startIndex+7] === 0x01) {
                        return new TappyFrameResult(buffer.slice(startIndex,startIndex+8),startIndex+7,false,false,true,false);
                    }
            else if(buffer[startIndex+5] === 0xFF &&
                    buffer[startIndex+6] === 0xFF &&
                    buffer[startIndex+7] === 0x02) {
                        return new TappyFrameResult(buffer.slice(startIndex,startIndex+8),startIndex+7,false,false,false,true);
                    }
        }

        // check if buffer has enough data
        var endIdxNonInc = startIndex+Tappy.FRAME_SIZE_NO_DATA+length;
        var endIdxInc = endIdxNonInc - 1;
        if(endIdxNonInc > buffer.length) {
            return new TappyFrameResult(null, -1, false, false, false, false);
        }

        var frame = buffer.slice(startIndex,endIdxNonInc);
        if(length === 0) {
            if(frame[frame.length-1] === 0x00) {
                return new TappyFrameResult(frame,endIdxInc,false,false, false, false);
            }
            else {
                return new TappyFrameResult(frame,endIdxInc,false,true, false, false);
            }
        }

        var dcsCount = 0;
        for(var dcs_i = 0; dcs_i < length; dcs_i++) {
            var checkIndex = startIndex+dcs_i+5;
            dcsCount += buffer[checkIndex];
        }
        dcsCount += frame[frame.length - 1];

        if((dcsCount % 256) !== 0) {
            return new TappyFrameResult(frame,endIdxInc,false, true, false, false);
        }
        else {
            return new TappyFrameResult(frame,endIdxInc,false, false, false, false);
        }
    };

    /**
     * Send a command to the tappy. This uses timeouts to try to make sure
     * that the buffer isn't full of invalid data from a previous response.
     *
     * Note that use of this does not prevent you from using the sendRaw or
     * sendCommand, so please consistently use either the safeSendRaw/safeSendCommand
     * pair or use the non-safe pair with your own error handling. Additionally,
     * safeSendCommand internally uses safeSendRaw, so they operate on the same timeouts.
     *
     * @throws if the command is too long
     * @throws if the tappy is not connected
     * @param {integer} commandCode 8-bit command code to send to tappy
     * @param {Uint8Array} params the parameters for the command if any
     * @param {callbacks} TappyCallbacks if you want to set new callbacks
     */
    Tappy.prototype.safeSendCommand = function(commandCode, params, callbacks) {
        // length includes command code
        if(params.length > 65534) {
            throw "Command too long";
        }

        if(typeof callbacks === "object") {
            this.safeSendRaw(this.composeCommand(commandCode,params),callbacks);
        }
        else {
            this.safeSendRaw(this.composeCommand(commandCode,params));
        }
    };

    /**
     * Send raw data to the Tappy. This uses timeouts to try to make sure
     * that the buffer isn't full of invalid data from a previous response.
     *
     * Note that use of this does not prevent you from using the sendRaw or
     * sendCommand, so please cosisntently use either the safeSendRaw/safeSendCommand
     * pair or use the non-safe pair with your own error handling. Additionally,
     * safeSendCommand internally uses safeSendRaw, so they operate on the same timeouts.
     *
     * @throws if you attempt to send without being connected
     * @throws if you try to send undefined
     * @param {ArrayBuffer} data the bytes to send to the tappy
     * @param {callbacks} TappyCallbacks if you want to set new callbacks
     */
    Tappy.prototype.safeSendRaw = function(data, callbacks) {
        var self = this;
        if(typeof data === "undefined") {
            //should probably be more exacting
            throw "Cannot send no data";
        }
        if(!this.isConnected()) {
            throw "Cannot send while not connected";
        }

        var postSetCallbacks = null;
        if(typeof callbacks === 'object' && callbacks !== null) {
            var defaultCallbacks = new TappyCallbacks();
            var newCallbacks = callbacks || {};
            for (var opt in defaultCallbacks) {
                if (defaultCallbacks.hasOwnProperty(opt) && !newCallbacks.hasOwnProperty(opt)) {
                    newCallbacks[opt] = defaultCallbacks[opt];
                }
            }
            postSetCallbacks = newCallbacks;
        }
        else {
            postSetCallbacks = this.callbacks;
        }

        // store the callbacks and command
        // for sending after the stop command
        this.pendingOperation = function() {
            self.callbacks = postSetCallbacks;
            self.log("Sending raw after wait command:");
            self.log(new Uint8Array(data));
            self.sendRaw(data);
        };

        // flush anything in the serial port and follow
        // it up with the pending operation
        var flushAndSend = function() {
            self.callbacks = new TappyCallbacks();
            chrome.serial.flush(self.connectionId, function(result) {
                self.callbacks = postSetCallbacks;
                self.log("Emptying buffer after reset, current state is");
                self.log(self.bufferedData);
                self.bufferedData = new Uint8Array(0);
                if(self.pendingOperation !== null) {
                    self.pendingOperation();
                    self.pendingOperation = null;
                }
            });
        };

        // temporarily replace all callbacks
        // with ones that trigger the pendingOperation
        var tempCallbacks = new TappyCallbacks();
        tempCallbacks.ackResponseCb = flushAndSend;
        tempCallbacks.nackResponseCb = flushAndSend;
        tempCallbacks.lcsErrorResponseCb = flushAndSend;
        tempCallbacks.dcsErrorResponseCb = flushAndSend;
        tempCallbacks.serialPortErrorCb = flushAndSend;
        tempCallbacks.validResponseFrameCb = function(frame) {
            // initiates send if the tappy errors
            self.log("Valid frame in transient time for safe send");
            self.log(frame);
            if(frame.length > 6) {
                if(frame[5] === 0x7F && frame[6] === Tappy.CommandCodes.STOP) {
                    self.log("Unrecognized command for STOP, this Tappy probably predates STOP");
                    flushAndSend();
                }
            }
        };

        this.log("Emptying buffer, current state is");
        this.log(this.bufferedData);
        this.bufferedData = new Uint8Array(0);
        this.callbacks = tempCallbacks;
        this.sendCommand(Tappy.CommandCodes.STOP);
    };

    /**
     * Send a command to the tappy
     *
     * @throws if the command is too long
     * @throws if the tappy is not connected
     * @param {integer} commandCode 8-bit command code to send to tappy
     * @param {Uint8Array} params the parameters for the command if any
     */
    Tappy.prototype.sendCommand = function(commandCode, params) {
        this.sendRaw(this.composeCommand(commandCode,params));
    };

    /**
     * Compose command into a raw frame
     *
     * @throws if the command is too long
     * @param {integer} commandCode 8-bit command code to send to tappy
     * @param {Uint8Array} params the parameters for the command if any
     */
    Tappy.prototype.composeCommand = function(commandCode, params) {
        // length includes command code
        if (typeof params === "undefined" || params === null) {
            params = new Uint8Array(0);
        }

        if(params.length > 65534) {
            throw "Command too long";
        }
        var command = new Uint8Array(7+params.length+this.preambleLength+this.postambleLength);

        var index = 0;
        for(var pr_i = 0; pr_i < this.preambleLength; pr_i++) {
            command[index] = 0x00; //this isn't really necessary
            index++;
        }

        // add command header
        command[index++] = 0x00;
        command[index++] = 0xFF;

        // send length bytes
        var dataLength = params.length + 1; // +1 to include the command code
        var l1 = Math.floor(dataLength / 256);
        var l2 = (dataLength) % 256;
        var lengthSum = l1+l2;
        // TODO: verify the binary representation
        var lcs = 256 - lengthSum;
        command[index++] = l1;
        command[index++] = l2;
        // lcs calculation
        command[index++] = lcs;

        command[index++] = commandCode;

        // add data while calculating dcs
        var dcsCounter = commandCode;
        for(var par_i = 0; par_i < params.length; par_i++) {
            command[index++] = params[par_i];
            dcsCounter += params[par_i];
        }

        command[index++] = 256 - (dcsCounter % 256);

        for(var po_i = 0; po_i < this.postambleLength; po_i++) {
            command[index] = 0x00; //this isn't really necessary
            index++;
        }

        return command.buffer;
    };

    /**
     * Send raw data
     *
     * @param {ArrayBuffer} data the bytes to send to the tappy
     * @throws if you attempt to send without being connected
     * @throws if you try to send undefined
     */
    Tappy.prototype.sendRaw = function(data) {
        if(typeof data === "undefined") {
            //should probably be more exacting
            throw "Cannot send no data";
        }
        if(!this.isConnected()) {
            throw "Cannot send while not connected";
        }
        else {
            var self = this;
            self.log("Attempting send:");
            self.log(new Uint8Array(data));
            chrome.serial.send(this.connectionId,data,function(sendInfo) {
                if(sendInfo.hasOwnProperty("error") && sendInfo.error !== null) {
                    self.log("A send error occured, received:");
                    self.log(sendInfo);
                    if(typeof self.callbacks.serialPortErrorCb === 'function') {
                        self.callbacks.serialPortErrorCb(sendInfo,data);
                    }
                }
            });
        }
    };

    /**
     * Set the callbacks used by this Tappy
     *
     * @param {TappyCallbacks} newCallbacks new callback set to use
     */
    Tappy.prototype.setCallbacks = function(newCallbacks) {
        var defaultCallbacks = new TappyCallbacks();
        var options = newCallbacks || {};
        for (var opt in defaultCallbacks) {
            if (defaultCallbacks.hasOwnProperty(opt) && !options.hasOwnProperty(opt)) {
                options[opt] = defaultCallbacks[opt];
            }
        }

        this.callbacks = options;
    };

    /**
     * Generate a standard callback that handles most command cases
     * This multiplexes all errors into the errorcallback
     *
     * @param {Tappy~successCallback} successCallback
     * @param {Tappy~errorCallback} errorCallback
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.generateStandardCallbacks = function(successCallback,errorCallback,ackCallback) {
        var nullFunction = function(){};
        successCallback = (typeof successCallback !== "undefined" && successCallback !== null) ? successCallback : nullFunction;
        errorCallback = (typeof errorCallback !== "undefined" && errorCallback !== null) ? errorCallback : nullFunction;
        ackCallback = (typeof ackCallback !== "undefined" && ackCallback !== null) ? ackCallback : nullFunction;

        var standardCallbacks = {};
        standardCallbacks.ackResponseCb = function() {
            ackCallback();
        };

        standardCallbacks.nackResponseCb = function() {
            errorCallback(Tappy.ErrorTypes.NACK,{});
        };

        standardCallbacks.lcsErrorResponseCb = function(buffer) {
            errorCallback(Tappy.ErrorTypes.LCS,{buffer: buffer});
        };

        standardCallbacks.dcsErrorResponseCb = function(frame) {
            errorCallback(Tappy.ErrorTypes.DCS,{frame: frame});
        };

        standardCallbacks.serialPortErrorCb = function(sendInfo, data) {
            errorCallback(Tappy.ErrorTypes.SERIAL,{sendInfo: sendInfo, data: data});
        };

        standardCallbacks.validResponseFrameCb = function(frame) {
            // chop start of ins (2 byte), l1 (1 byte), l2 (1 byte), lcs (1 byte) from start
            // dcs from end
            var unwrappedResponse = frame.slice(5,frame.length - 1);
            if(unwrappedResponse[0] === Tappy.APPLICATION_ERROR_CODE && unwrappedResponse.length >= 4) {
                var errorCode = unwrappedResponse[2];
                var detail = Tappy.getDetailForGlobalErrorCode(errorCode);
                if(detail !== null) {
                    errorCallback(Tappy.ErrorTypes.APPLICATION, {
                        commandCode: unwrappedResponse[1],
                        errorCode: unwrappedResponse[2],
                        nfcChipError: unwrappedResponse[3],
                        detail: detail});
                } else {
                    errorCallback(Tappy.ErrorTypes.APPLICATION, {
                        commandCode: unwrappedResponse[1],
                        errorCode: unwrappedResponse[2],
                        nfcChipError: unwrappedResponse[3]});
                }
            }
            else {
                successCallback(unwrappedResponse);
            }
        };

        return standardCallbacks;
    };

    /**
     * This callback is used when a valid frame is returned that is not a standard application
     * error.
     *
     * @callback Tappy~successCallback
     * @param {Uint8Array} response data deframed
     */

    /**
     * This callback is used when an error occured, either application level on the Tappy,
     * protocol-level in the communication, or hardware/driver level in Chrome.
     *
     * @callback Tappy~errorCallback
     * @param {integer} one of Tappy.ErrorTypes
     * @param {Object} error data depending on the type of error encountered
     *     NACK: object of params for TappyCallbacks~nackResponseCb
     *     LCS: object of params for TappyCallbacks~lcsErrorResponseCb
     *     DCS: object of params for TappyCallbacks~lcsErrorResponseCb
     *     SERIAL: object of params for TappyCallbacks~serialPortErrorCb
     *     APPLICATION:
     *     {
     *         commandCode: the command code that generated the error
     *         errorCode: the error code generated
     *         nfcChipError: the status from the PN532, 0x00 corresponds to no chip error
     *         detail: (optional) english description of the error
     *     }
     *     BAD_RESPONSE: available for command-specific parsers should provide the following
     *     {
     *         response: Uint8Array of the deframed response that caused the error
     *         detail: (optional) english language description of the issue
     *     }
     */

    /**
     * Get English detail description for global error codes
     *
     * @param {integer} errorCode
     * @returns {string} human-readable English description of error
     */
    Tappy.getDetailForGlobalErrorCode = function(errorCode) {
        var detail = null;
        switch(errorCode) {
            case 0x01:
                detail = "Invalid content slot number.";
                break;
            case 0x02:
                detail = "Invalid content type.";
                break;
            case 0x03:
                detail = "NDEF message too big";
                break;
            case 0x04:
                detail = "vCard lengths not received";
                break;
            case 0x05:
                detail = "vCard length mismatch";
                break;
            case 0x06:
                detail = "vCard delimiters missing";
                break;
            case 0x07:
                detail = "vCard parameter length mismatch";
                break;
            case 0x08:
                detail = "A scanning error has occurred.";
                break;
            case 0x09:
                detail = "An unrecognized command has been given.";
                break;
            case 0x0A:
                detail = "Invalid content slot order for export";
                break;
            case 0x0B:
                detail = "Content slot was not populated with content.";
                break;
            case 0x0C:
                detail = "NDEF formatting error - the OTP bytes are already set to non-NDEF.";
                break;
            case 0x0D:
                detail = "The tag appears to be locked and cannot be written.";
                break;
            case 0x0E:
                detail = "Unsupported tag type";
                break;
            case 0x0F:
                detail = "An error occured locking the tag";
                break;
            case 0x10:
                detail = "Tag operation timed out";
                break;
            case 0x11:
                detail = "An error occured formatting MIFARE Classic application directory sector trailer";
                break;
            case 0x12:
                detail = "An error occured MIFARE Classic sector trailer for NDEF";
                break;
            case 0x13:
                detail = "An error occured writing MIFARE Classic data blocks";
                break;
            case 0x14:
                detail = "Incorrect NONCE size";
                break;
            case 0x15:
                detail = "No previous packet";
                break;
            case 0x16:
                detail = "Invalid picker number";
                break;
            case 0x17:
                detail = "Error adding picker tag";
                break;
            case 0x18:
                detail = "Error getting bin count";
                break;
            case 0x19:
                detail = "Error clearing bin count";
                break;
            case 0x1A:
                detail = "Tag already allocated";
                break;
            case 0x1B:
                detail = "Secondary oscillator not ready, cannot set date/time";
                break;
            case 0x1C:
                detail = "Real-time clock not ready";
                break;
            case 0x1D:
                detail = "Tag not wristband compatible";
                break;
            case 0x1E:
                detail = "Guest data data out of bounds";
                break;
            case 0x1F:
                detail = "Guest number exceeds maximum";
                break;
            case 0x20:
                detail = "An error occured creating guest wristband";
                break;
            case 0x21:
                detail = "An error occured reading guest count";
                break;
            case 0x22:
                detail = "Counter number invalid";
                break;
            case 0x23:
                detail = "Error clearing wristband counter";
                break;
            case 0x24:
                detail = "Out of bounds";
                break;
            case 0x25:
                detail = "Authentication failed";
                break;
            case 0x26:
                detail = "Error reading passport datagroup";
                break;
            case 0x27:
                detail = "Incorrect number of parameters";
                break;
            case 0x28:
                detail = "Provisioning failed";
                break;
            case 0x29:
                detail = "An error occured while attempting to format tag as NDEF";
                break;
            case 0x2A:
                detail = "Field number exceeds maximum";
                break;
            case 0x2B:
                detail = "Field number not set";
                break;
            case 0x2C:
                detail = "Improper URL format";
                break;
            case 0x2D:
                detail = "Required URL not set";
                break;
            case 0x2E:
                detail = "Corrupt field data";
                break;
            case 0x2F:
                detail = "Required field not set";
                break;
            case 0x30:
                detail = "Multirecord text field number exceeds maximum";
                break;
            case 0x31:
                detail = "Multirecord text field number not set";
                break;
            case 0x32:
                detail = "Multirecord text field not set";
                break;
            case 0x33:
                detail = "Multirecord text field data corrupted";
                break;
            case 0x34:
                detail = "Invalid password diversification method";
                break;
            case 0x35:
                detail = "Incorrect salt length";
                break;
            case 0x36:
                detail = "Formatting error";
                break;
            case 0x37:
                detail = "No NDEF data found";
                break;
            case 0x38:
                detail = "Unrecognized NDEF version";
                break;
            case 0x39:
                detail = "Problem reading NDEF data";
                break;
            case 0x3A:
                detail = "Incorrect UID length for password diversification";
                break;
            case 0xFC:
                detail = "A unknown error has occurred.";
                break;
            default:
                detail = "A unrecognized error has occurred.";
                break;
        }
        return detail;
    };

    /**
     * Extends Tappy prototype to add additional commands 
     *
     * @version 2.0.0
     */

    Tappy.CommandCodes.ADD_CONTENT = 0x02;
    Tappy.CommandCodes.EMULATE_CONTENT = 0x03;
    Tappy.CommandCodes.READ_TAG_UID = 0x07;
    Tappy.CommandCodes.WRITE_TAG = 0x08;
    Tappy.CommandCodes.WRITE_TEXT_NDEF = 0x09;
    Tappy.CommandCodes.READ_NDEF = 0x26;
    Tappy.CommandCodes.LOCK_TAG = 0x13;
    Tappy.CommandCodes.WRITE_CUSTOM_NDEF = 0x29;
    Tappy.CommandCodes.SCAN_TYPE_4B = 0x2A;

    /**
     * Inform the Tappy to scan for a tag entering its field
     *
     * @param {integer} timeout the number of seconds to wait before timing out on request,
     * up to a max of 255 seconds, 0 disables timeout
     *
     * @param {boolean} enumerate whether the Tappy should attempt to enumerate the exact
     * technology for tags that are not positively identified during the anti-collision.
     * This takes time and may impair read performance.
     *
     * @param {callback} successCallback function(tagType integer, tagCode Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.readTagUid = function(timeout,enumerate,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is tag type+tag code length+4 byte tag code
            if(resolvedFrame.length < 5) {
                errorCb(Tappy.ErrorTypes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var tagType = resolvedFrame[0];
                var tagCodeLength = resolvedFrame[1];
                var tagCode = resolvedFrame.slice(2,2+tagCodeLength);
                if(tagCode.length != 4 && tagCode.length != 7 && tagCode.length != 10) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Tag code is an invalid length"});
                } else {
                    successCb(tagType,tagCode);
                }
            }
        };
        var enumerateFlag = enumerate ? 0x00 : 0x01;

        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.READ_TAG_UID, new Uint8Array([timeout,enumerateFlag]), callbackSet);
    };

    /**
     * Inform the Tappy to scan for an NDEF-formatted tag entering its field
     *
     * @param {integer} timeout the number of seconds to wait before timing out on request,
     * up to a max of 255 seconds, 0 disables timeout
     *
     * @param {callback} successCallback function(tagType integer, tagCode Uint8Array, ndefMessage Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.readNdef = function(timeout,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is tag type+tag code length+ 4 byte tag code
            if(resolvedFrame.length < 6) {
                errorCb(Tappy.ErrorCodes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var tagType = resolvedFrame[0];
                var tagCodeLength = resolvedFrame[1];

                // This should probably also get a frame that takes into account the minimum ndef message length
                if(tagCodeLength != 4 && tagCodeLength != 7 && tagCodeLength != 10) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Tag code is an invalid length"});
                } else if (resolvedFrame.length < (2+tagCodeLength)) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Frame too short to contain tag code"});
                } else {
                    var tagCode = resolvedFrame.slice(2,2+tagCodeLength);
                    var rawNdefMessage = resolvedFrame.slice(2+tagCodeLength);
                    var parsedNdefMessage = null;
                    try {
                        parsedNdefMessage = Ndef.Message.fromBytes(rawNdefMessage);
                    } catch (err) {
                        errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                            response: resolvedFrame,
                            detail: "Exception thrown attempting to parse: "+err});
                        return;
                    }

                    if(parsedNdefMessage !== null) {
                        successCb(tagType,tagCode,parsedNdefMessage);
                    }
                    else {
                        errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                            response: resolvedFrame,
                            detail: "NdefMessage parse to failed"});
                    }
                }

            }
        };

        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.READ_NDEF, new Uint8Array([timeout]), callbackSet);
    };

    /**
     * These are used to inform the tappy what kind of content you are adding
     */
    Tappy.ContentSlotTypes = {
        URI: 0x01,
        TEXT: 0x02,
        VCARD: 0x04,
        EMPTY: 0x99
    };

    /**
     * Add content to one of the Tappy's internal content slots
     * These are persistent until the Tappy is restarted or reset, so you
     * can use them for batch encoding without sending the content multiple times
     * There are 10 slots on the Tappy, numbered 0-9
     *
     * @param {integer} contentSlot the slot to add to
     * @param {Tappy.ContentSlotTypes} contentSlot the type of content being added
     * @param {integer} uriCode the uri code for the content if relevant
     * @param {Uint8Array} data the raw data to add to the content slot
     * @param {callback} successCallback function() called on ACK
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.addContent = function(contentSlot,contentType,uriCode,data,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var params = new Uint8Array(3+data.length);
        params[0] = contentSlot;
        params[1] = contentType;
        params[2] = uriCode;
        params.set(data,3);

        var wrappedErrorCb = function(type, data) {
            if(type === Tappy.ErrorTypes.APPLICATION) {
                if(data.commandCode === Tappy.CommandCodes.ADD_CONTENT && data.errorCode === 0x03) {
                    data.detail ="NDEF message too big (exceeds 8096 bytes).";
                }
            }
            errorCb(type,data);
        };

        var wrappedAckCb = function() {
            successCb();
            ackCallback();        
        };

        var callbackSet = Tappy.generateStandardCallbacks(successCb,wrappedErrorCb,wrappedAckCb);
        this.safeSendCommand(Tappy.CommandCodes.ADD_CONTENT, params, callbackSet);
    };

    /**
     * Data type exposing the different properties that the Tappy
     * vCard writing convenience function supports. If you wish to use
     * additional vCard properties or a different vCard format,
     * please use the Tappy.writeCustomNdef command and compose your
     * NDEF message manually.
     */
    Tappy.TappyVcard = function() {
        this.name = "";
        this.cellPhone = "";
        this.workPhone = "";
        this.homePhone = "";
        this.personalEmail = "";
        this.businessEmail = "";
        this.homeAddress = "";
        this.workAddress = "";
        this.company = "";
        this.title = "";
        this.url = "";
    };

    /** 
     * Adds a valid vCard to a content slot.
     * This is justa  convenience function around 
     * Tappy.addContent, so general behaviour will be quite similar
     *
     * @param {integer} contentSlot the slot to add to
     * @param {Tappy.TappyVcard} vcard the vcard content to add
     * @param {callback} successCallback function() called on ACK
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.addVcardContent = function (contentSlot,vcard,successCb,errorCb,ackCallback) {
        var emptyVcard = new Tappy.TappyVcard();
        var finalVcard = vcard || {};
        for (var opt in emptyVcard) {
            if (emptyVcard.hasOwnProperty(opt) && !finalVcard.hasOwnProperty(opt)) {
                finalVcard[opt] = emptyVcard[opt];
            }
        }

        var contentLen = 10; // for the commas between fields
        var nameArr = TappyUtils.stringToUint8Array(vcard.name);
        contentLen += nameArr.length;

        var cellPhArr = TappyUtils.stringToUint8Array(vcard.cellPhone);
        contentLen += cellPhArr.length;

        var workPhArr = TappyUtils.stringToUint8Array(vcard.workPhone);
        contentLen += workPhArr.length;

        var homePhArr = TappyUtils.stringToUint8Array(vcard.homePhone);
        contentLen += homePhArr.length;

        var persEmArr = TappyUtils.stringToUint8Array(vcard.personalEmail);
        contentLen += persEmArr.length;

        var busEmArr = TappyUtils.stringToUint8Array(vcard.businessEmail);
        contentLen += busEmArr.length;

        var homeAdrArr = TappyUtils.stringToUint8Array(vcard.homeAddress);
        contentLen += homeAdrArr.length;

        var workAdrArr = TappyUtils.stringToUint8Array(vcard.workAddress);
        contentLen += workAdrArr.length;

        var compArr = TappyUtils.stringToUint8Array(vcard.company);
        contentLen += compArr.length;

        var titleArr = TappyUtils.stringToUint8Array(vcard.title);
        contentLen += titleArr.length;

        var urlArr = TappyUtils.stringToUint8Array(vcard.url);
        contentLen += urlArr.length;

        var contentIdx = 0;
        var contentArr = new Uint8Array(contentLen);
        contentArr.set(nameArr,contentIdx);
        contentIdx+=nameArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(cellPhArr,contentIdx);
        contentIdx+=cellPhArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(workPhArr,contentIdx);
        contentIdx+=workPhArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(homePhArr,contentIdx);
        contentIdx+=homePhArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(persEmArr,contentIdx);
        contentIdx+=persEmArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(busEmArr,contentIdx);
        contentIdx+=busEmArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(homeAdrArr,contentIdx);
        contentIdx+=homeAdrArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(workAdrArr,contentIdx);
        contentIdx+=workAdrArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(compArr,contentIdx);
        contentIdx+=compArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(titleArr,contentIdx);
        contentIdx+=titleArr.length;
        contentArr[contentIdx++] = 0x2c;

        contentArr.set(urlArr,contentIdx);
        contentIdx+=urlArr.length;

        var params = new Uint8Array(12+contentLen);
        // the next byte must be non-ascii due to Tappy idiosyncrasies 
        params[0] = 0x80;
        params[1] = nameArr.length;
        params[2] = cellPhArr.length;
        params[3] = workPhArr.length;
        params[4] = homePhArr.length;
        params[5] = persEmArr.length;
        params[6] = busEmArr.length;
        params[7] = homeAdrArr.length;
        params[8] = workAdrArr.length;
        params[9] = compArr.length;
        params[10] = titleArr.length;
        params[11] = urlArr.length;
        params.set(contentArr,12);

        this.addContent(contentSlot,Tappy.ContentSlotTypes.VCARD,0x00,params,successCb,errorCb,ackCallback);
    };

    /** 
     * Adds a textual content to a content slot.
     * This is just a  convenience function around 
     * Tappy.addContent, so general behaviour will be quite similar
     *
     * @param {integer} contentSlot the slot to add to
     * @param {Tappy.ContentSlotTypes} contentSlot the type of content being added
     * @param {integer} uriCode the uri code for the content if relevant
     * @param {string} textual content to put in the slot
     * @param {callback} successCallback function() called on ACK
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.addTextContent = function(contentSlot,contentType,uriCode,text,successCb,errorCb,ackCallback) {
        var strToByte = function(string) {
            var escstr = encodeURIComponent(string);
            var binstr = escstr.replace(/%([0-9A-F]{2})/g, function(match, p1) {
                return String.fromCharCode('0x' + p1);
            });
            var ua = new Uint8Array(binstr.length);
            Array.prototype.forEach.call(binstr, function (ch, i) {
                ua[i] = ch.charCodeAt(0);
            });
            return ua;
        };
        this.addContent(contentSlot,contentType,uriCode,strToByte(text),successCb,errorCb,ackCallback);
    };

    /** 
     * Write a single text record to a tag 
     *
     * This is a simpler way to encode tags when you wish to just write a single
     * text record to a tag. The record will be configured 
     *
     * @param {integer} timeout seconds for the tappy to wait to encounter the tag, 255
     * max, 0 disables
     * @param {boolean} lock whether or not the tag should be locked 
     * @param {string} text the textual content to put on the tag 
     * @param {callback} successCallback function(tagType integer, tagCode Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.writeTextNdef = function(timeout,lock,text,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is tag type+tag code length+4 byte tag code
            if(resolvedFrame.length < 5) {
                errorCb(Tappy.ErrorTypes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var tagType = resolvedFrame[0];
                var tagCodeLength = resolvedFrame[1];
                var tagCode = resolvedFrame.slice(2,2+tagCodeLength);
                if(tagCode.length != 4 && tagCode.length != 7 && tagCode.length != 10) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Tag code is an invalid length"});
                } else {
                    successCb(tagType,tagCode);
                }
            }
        };

        var textArray = TappyUtils.stringToUint8Array(text);

        var params = new Uint8Array(2+textArray.length);
        params[0] = timeout;
        params[1] = lock ? 0x01 : 0x00;
        params.set(textArray,2);

        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.WRITE_TEXT_NDEF, params, callbackSet);
    };

    /** 
     * Emulates a tag using content currently stored in a content slot.
     * Note that not all Tappies support this operation
     *
     * @param {integer} contentSlot the slot to add to
     * @param {boolean} interrupt whether to allow the tappy to be interrupted 
     * once emulation starts. If set to false, the tappy will continue emulating until
     * numScan or the timeout is reached. If both of those are set to 0x00, the tappy
     * will not stop emulating until power is cycled
     * @param {integer} numScan the number of scans to emulate the content for up to 255 scans. 0 disables 
     * @param {integer} timeout the amount of time to emulate for up to up to 65535 seconds, 0 disables
     * @param {callback} successCallback function() called on ACK
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.emulateContent = function(contentSlot, interrupt, numScan, timeout, successCb, errorCb, ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var params = new Uint8Array(5);
        params[0] = contentSlot;
        params[1] = interrupt ? 0x01 : 0x00;
        params[2] = numScan;
        params[3] = (timeout >> 8) & 0xFF;
        params[4] = (timeout) & 0xFF;

        var wrappedAckCb = function() {
            successCb();
            ackCallback();        
        };

        var callbackSet = Tappy.generateStandardCallbacks(successCb,errorCb,wrappedAckCb);
        this.safeSendCommand(Tappy.CommandCodes.EMULATE_CONTENT, params, callbackSet);
    };

    /** 
     * Write content out of a content slot to a tag 
     *
     * This is a simpler way to encode tags when you wish to just write a single
     * text record to a tag. The record will be configured 
     *
     * @param {integer} timeout seconds for the tappy to wait to encounter the tag, 255
     * max, 0 disables
     * @param {boolean} lock whether or not the tag should be locked 
     * @param {callback} successCallback function(tagType integer, tagCode Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.writeContentToTag = function(contentSlot,lock,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is tag type+lock flag+tag code length+ 4 byte tag code
            if(resolvedFrame.length < 7) {
                errorCb(Tappy.ErrorCodes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var tagType = resolvedFrame[0];
                var lockout = resolvedFrame[1] !== 0x00;
                var tagCodeLength = resolvedFrame[2];

                if(tagCodeLength != 4 && tagCodeLength != 7 && tagCodeLength != 10) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Tag code is an invalid length"});
                } else if (resolvedFrame.length < (3+tagCodeLength)) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Frame too short to contain tag code"});
                } else {
                    var tagCode = resolvedFrame.slice(3,3+tagCodeLength);
                    successCb(tagType,tagCode,lockout);
                }

            }
        };

        var params = new Uint8Array(10);
        params[0] = contentSlot;
        params[1] = lock ? 0x01 : 0x00;

        for(var i = 2; i < 10; i++) {
            params[i] = 0x00;
        }

        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.WRITE_TAG, params, callbackSet);
    };

    /** 
     * Send a stop command to the Tappy
     *
     * This tells the Tappy to stop whatever its doing and clear its buffers
     *
     * @param {callback} successCallback this is called on ACK 
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.sendStop = function(successCb,errorCb,ackCallback) {
        var params = new Uint8Array(0);

        var wrappedAckCb = function() {
            successCb();
            ackCallback();        
        };
        var callbackSet = Tappy.generateStandardCallbacks(successCb,errorCb,wrappedAckCb);
        this.safeSendCommand(Tappy.CommandCodes.STOP, params, callbackSet);
    };

    /** 
     * Lock a Type 2 tag. If you are not familiar with Type 2 locking, it is advisable
     * to look it up as this is an irreversible operation.
     *
     * @param {integer} timeout seconds for the tappy to wait to encounter the tag, 255
     * max, 0 disables
     * @param {callback} successCallback function(tagType integer, tagCode Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.lockTag = function(timeout,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is tag type+tag code length+ 4 byte tag code
            if(resolvedFrame.length < 6) {
                errorCb(Tappy.ErrorCodes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var tagType = resolvedFrame[0];
                var tagCodeLength = resolvedFrame[1];

                if(tagCodeLength != 4 && tagCodeLength != 7 && tagCodeLength != 10) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Tag code is an invalid length"});
                } else if (resolvedFrame.length < (2+tagCodeLength)) {
                    errorCb(Tappy.ErrorTypes.BAD_RESPONSE,{
                        response: resolvedFrame,
                        detail: "Frame too short to contain tag code"});
                } else {
                    var tagCode = resolvedFrame.slice(2,2+tagCodeLength);
                    successCb(tagType,tagCode);
                }

            }
        };

        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.LOCK_TAG, new Uint8Array([timeout]), callbackSet);
    };

    /** 
     * Write custom NDEF content to a tag 
     *
     * If you wish to have finer grained control over NDEF writing, this command can be used
     * Note that the Tappy will determine how to configure the capability container based on
     * the NDEF content, so the content should only contain an NDEF message
     *
     * @param {integer} timeout seconds for the tappy to wait to encounter the tag, 255
     * max, 0 disables
     * @param {boolean} lock whether or not the tag should be locked 
     * @param {Uint8Array} content byte array representation of an NDEF message
     * @param {callback} successCallback function(tagType integer, tagCode Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.writeCustomNdef = function(timeout,lock,content,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is tag type+4 byte tag code
            if(resolvedFrame.length < 5) {
                erroParserCb(Tappy.ErrorCodes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var tagType = resolvedFrame[0];
                var tagCode = resolvedFrame.slice(1);

                successCb(tagType,tagCode);
            }
        };
        var params = new Uint8Array(2+content.length);
        params[0] = timeout;
        params[1] = lock ? 0x01 : 0x00;
        params.set(content,2);

        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.WRITE_CUSTOM_NDEF, params, callbackSet);
    };

    /**
     * Scan for a Type 4 tag using Type B modulation entering the Tappy's field
     *
     * @param {integer} timeout the number of seconds to wait before timing out on request,
     * up to a max of 255 seconds, 0 disables timeout
     * @param {callback} successCallback function(atqb Uint8Array, attrib Uint8Array)
     * @param {Tappy~errorCallback} errorCb
     * @param {Tappy~ackCallback} ackCallback
     */
    Tappy.prototype.scanType4B = function(timeout,successCb,errorCb,ackCallback) {
        successCb = typeof successCb === "function" ? successCb : function(){};
        errorCb = typeof errorCb === "function" ? errorCb : function(){};
        ackCallback = typeof ackCallback === "function" ? ackCallback : function(){};

        var successParseCb = function(resolvedFrame) {
            // minimum length is atqb+attrib
            if(resolvedFrame.length < 2) {
                errorCb(Tappy.ErrorTypes.BAD_PARSE,{response:resolvedFrame});
            } else {
                var atqbLen = resolvedFrame[0];
                var attribLen = resolvedFrame[1];
                if(resolvedFrame.length < (2+atqbLen+attribLen)) {
                    errorCb(Tappy.ErrorTypes.BAD_PARSE,{response:resolvedFrame});
                }
                else {
                    var atqb = resolvedFrame.slice(2,2+atqbLen);
                    var attrib = resolvedFrame.slice(2+atqbLen,2+atqbLen+attribLen);
                    successCb(atqb,attrib);
                }
            }
        };
        var callbackSet = Tappy.generateStandardCallbacks(successParseCb,errorCb,ackCallback);
        this.safeSendCommand(Tappy.CommandCodes.SCAN_TYPE_4B, new Uint8Array([timeout]), callbackSet);
    };


    /**
     * Object for automatically detecting Tappies.
     * Depends on Tappy2
     *
     *  @version 1.0.2
     * TODO: Make the delegates communicate back to the detector when they're all done
     */
    var TappyAutodetector = function (){
        this.isCancelled = true;
        this.detectedCallback = null;

        // This value determines how long to wait for an ACK before giving up
        //
        // Current value was determined empirically based on a handful of,
        // test cases, so it may need additional tuning.
        //
        // The Tappy itself should only take a few ms to respond
        // to this command, but the various buffers and serial port defaults
        // on the system increase the time it takes for a reliable detection:
        //
        // Linux (Mint 17.2): Decent at 10ms, solid at 15+
        // Windows (XP, 7, 10): Unreliable at 30ms, solid at 50+
        //
        // Therefore, the initial value was set to 100ms to provide a margin
        // of safety if there are Windows machines that have even worse serial
        // port latency than those tested.
        this.ackWaitTimeout = 100;

        // This callback is called when the autodetector status changes
        // see setStatusCallback
        this.statusCallback = null;

        // This is used for associating scan results with the scan that kicked
        // them off. It should not be externally modified
        this.latestScanId = 0;
    };

    /**
     * Set the callback for a Tappy detector
     *
     * @param {function} onTappyDetectedCb callback that takes a chrome deviceInfo
     */
    TappyAutodetector.prototype.setCallback = function(onTappyDetectedCb) {
        if(typeof onTappyDetectedCb !== 'function' && onTappyDetectedCb !== null) {
            throw "Callback must be a function or null";
        }

        this.detectedCallback = onTappyDetectedCb;
    };

    /**
     * Set the callback for a tappy detector status changed 
     *
     * @param {function} onStatusChangedCb callback that takes boolean that is true if scanning, false otherwise
     */
    TappyAutodetector.prototype.setStatusCallback = function(onStatusChangedCb) {
        if(typeof onStatusChangedCb !== 'function' && onStatusChangedCb !== null) {
            throw "Callback must be a function or null";
        }

        this.statusCallback = onStatusChangedCb;
    };

    /**
     * Cancels a scan. The scan may continue in callbacks briefly,
     * but no results will be returned any more
     */
    TappyAutodetector.prototype.cancelScan = function() {
        var self = this;
        self.isCancelled = true;
        self.notifyListenerOfStatus();
    };

    /**
     * Determine if this autodetector's scan has been cancelled
     */
    TappyAutodetector.prototype.isScanCancelled = function() {
        return this.isCancelled;
    };

    /**
     * Determine if the autodetecetor is currently scanning
     */
    TappyAutodetector.prototype.isScanning = function() {
        return !this.isScanCancelled();
    };

    /**
     * Internal function for notifying the listener of a found Tappy
     */
    TappyAutodetector.prototype.notifyListenerOfTappy = function(deviceInfo) {
        if(!this.isCancelled && this.detectedCallback !== null) {
            this.detectedCallback(deviceInfo);
        }
    };

    /**
     * Notify listener of a status change
     */
    TappyAutodetector.prototype.notifyListenerOfStatus = function() {
        if(this.statusCallback !== null) {
            this.statusCallback(this.isScanning());
        }
    };

    /**
     * Get the id for the latest scan kicked off in this autodetector
     */
    TappyAutodetector.prototype.getLatestScanId = function() {
        return this.latestScanId;
    };

    /**
     * Initiate a scan for Tappy devices.
     */
    TappyAutodetector.prototype.startScan = function () {
        var self = this;
        self.latestScanId++;
        var currentScanId = self.latestScanId;
        self.isCancelled = false;
        self.notifyListenerOfStatus();
        chrome.serial.getDevices(function (deviceList) {
            var ch = new TappyAutodetector.Channel(currentScanId,deviceList.length,self);
            for(var dv_i = 0; dv_i < deviceList.length && !self.isCancelled; dv_i++) {
                var deviceInfo = deviceList[dv_i];
                console.log("Trying");
                console.log(deviceInfo);
                var detector = new TappyAutodetector.DeviceDelegate(deviceInfo,ch,self.ackWaitTimeout);
                detector.initiate();
            }
            if(deviceList.length === 0) {
                self.cancelScan();
            }
        });
    };


    /**
     * Communication channel
     *
     * This is used enable listener notification on a failed scan as well
     * as forward successes through to the listener as long as the scan id matches
     */
    TappyAutodetector.Channel = function(channelScanId, totalDeviceCount, detector) {
        this.channelScanId = channelScanId;
        this.deviceCheckedCount = 0;
        this.totalDeviceCount = totalDeviceCount;
        this.detector = detector;
    };

    /**
     * Pass a notification of a valid tappy discovery through to the listener as long
     * as the autodetector's current scan id is the same as this channel's
     */
    TappyAutodetector.Channel.prototype.notifyListenerOfTappy = function(device) {
        var self = this;
        self.deviceCheckedCount++;
        if(self.detector.getLatestScanId() === self.channelScanId) {
            self.detector.notifyListenerOfTappy(device);
        }
    };

    /**
     * Cancel the scan once all devices have either succeeded or timed out
     * as long as the channel id matches the current scan id
     */
    TappyAutodetector.Channel.prototype.deviceCheckCompleted = function() {
        var self = this;
        if(self.deviceCheckedCount === self.totalDeviceCount && 
                self.detector.getLatestScanId() === self.channelScanId) {
                    self.detector.cancelScan();
                }
    };

    /**
     * Determine if this channel wishes to abort
     */
    TappyAutodetector.Channel.prototype.abortDesired = function () {
        var self = this;
        return self.detector.isScanCancelled() || self.detector.getLatestScanId() !== self.channelScanId;
    };

    /**
     * This is a delegate that wraps auto detection for sccoping reasons
     * should probably be a function not an object
     */
    TappyAutodetector.DeviceDelegate = function(deviceInfo, channel, timeout) {
        this.device = deviceInfo;
        this.channel = channel;
        this.tappy = new Tappy(deviceInfo.path);
        this.timeout = timeout;
    };

    /**
     * Start the search
     */
    TappyAutodetector.DeviceDelegate.prototype.initiate = function() {
        var self = this;
        self.tappy.connect(function() {
            if(!self.tappy.isConnected() || self.channel.abortDesired()) {
                self.tappy.disconnectAsap();
                self.channel.deviceCheckCompleted();
            }
            else {
                var resetIns = Tappy.RAW_RESET_INS;

                self.tappy.setCallbacks({
                    ackResponseCb: function() {
                        self.tappy.disconnectAsap();
                        self.channel.notifyListenerOfTappy(self.device);
                    }
                });
                self.tappy.sendRaw(resetIns.buffer);

                setTimeout(function() {
                    self.tappy.disconnectAsap();
                    self.channel.deviceCheckCompleted();
                },self.timeout);
            }
        });
    };

    Tappy.Autodetector = TappyAutodetector;
    Tappy.Utils = TappyUtils;
    return Tappy;
}));
