//
//  RKSessionWrapper.m
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import "RKSessionWrapper.h"

const NSInteger RKNullPortNumberSentinel = -1;
NSString * const RKErrorDomain = @"RKErrorDomain";
NSString * const RKErrorTitle = @"RKErrorTitle";
NSString * const RKErrorDescription = @"RKErrorDescription";
NSString * const RKWrapperPortPattern = @"Server running at http://.*?:(\\d+)";
NSString * const RKWrapperErrorPattern = @"([a-z]*?Error):\\s?(.*?)$";

/** Used to look for webconsole port number in rekall's stderr. */
static NSRegularExpression *RKWrapperPortRegex;

/** Used to look for python exceptions and errors in rekall's stderr. */
static NSRegularExpression *RKWrapperErrorRegex;

@interface RKSessionWrapper ()

@property (assign, readwrite) NSInteger port; // override to make readwrite

/** Handle to the rekall python process. */
@property (retain) NSTask *rekallTask;

/** Pipe to rekall's stderr output. */
@property (retain) NSPipe *rekallStdErr;

/** Buffer that holds recent stderr output from rekall. */
@property (retain) NSMutableString *rekallStdErrString;

/** Will attempt to extract the webconsole port, or an error message from rekall's stderr. */
- (void)tryExtractWebconsoleAddress;

@end


@implementation RKSessionWrapper

@synthesize port, rekallTask, rekallStdErr, rekallStdErrString, onLaunchCallback, onErrorCallback;

- (id)init {
    if(![super init]) {
        return nil;
    }
    
    self.port = RKNullPortNumberSentinel;
    
    return self;
}

- (void)tryExtractWebconsoleAddress {
    NSLog(@"Parsing rekall stderr output for errors and bind info.");
    
    if(!RKWrapperPortRegex) {
        // Initialize regular expressions only once.
        RKWrapperErrorRegex = [NSRegularExpression
                               regularExpressionWithPattern:RKWrapperErrorPattern
                                                    options:NSRegularExpressionCaseInsensitive
                                                      error:nil];

        RKWrapperPortRegex = [NSRegularExpression
                              regularExpressionWithPattern:RKWrapperPortPattern
                                                   options:NSRegularExpressionCaseInsensitive
                                                     error:nil];
    }
    
    NSTextCheckingResult *match;
    
    // First, check for errors in the stderr buffer.
    match = [RKWrapperErrorRegex firstMatchInString:self.rekallStdErrString
                                           options:0
                                             range:(NSRange) {0, self.rekallStdErrString.length}];
    
    if(match) {
        // We found an error message. Create an NSError and call the appropriate callback.
        NSString *errorTitle = [self.rekallStdErrString substringWithRange:[match rangeAtIndex:1]];
        NSString *errorDesc = [self.rekallStdErrString substringWithRange:[match rangeAtIndex:2]];
        NSLog(@"Rekall error: %@\n%@", errorTitle, errorDesc);
        
        if (self.onErrorCallback) {
            NSError *error = [NSError errorWithDomain:RKErrorDomain
                                                 code:RKSessionRekallError
                                             userInfo:[NSDictionary dictionaryWithObjectsAndKeys:
                                                       errorTitle,
                                                       RKErrorTitle,
                                                       errorDesc,
                                                       RKErrorDescription,
                                                       nil]];
            self.onErrorCallback(error);
        }
        
        // Always flush the stderr buffer when we find a match.
        [self.rekallStdErrString setString:@""];
        
        return;
    }
    
    // No errors - look for the port number.
    match = [RKWrapperPortRegex firstMatchInString:self.rekallStdErrString
                                           options:0
                                             range:(NSRange) {0, self.rekallStdErrString.length}];
    
    if(!match) {
        // No port number and no errors - we need more stuff in our buffer. Wait.
        return;
    }
    
    // Port number found - parse it out and report to the callback.
    
    NSString *result = [self.rekallStdErrString substringWithRange:[match rangeAtIndex:1]];
    NSLog(@"Match found: %@", result);
    
    NSInteger scannedPortNumber;
    NSScanner *scanner = [NSScanner scannerWithString:result];
    [scanner scanInteger:&scannedPortNumber];
    self.port = scannedPortNumber;
    
    // Flush on match.
    [self.rekallStdErrString setString:@""];
    
    // Execute callback since we found the port number.
    if(self.onLaunchCallback) {
        self.onLaunchCallback();
    }
}

- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf {
    // There shouldn't be a rekall instance already running, but let's err on the side of caution,
    // since we don't want to leave orphaned processes lying around.
    [self stopRekallWebconsoleSession];
    
    // Path to the rekall (rekal) executable.
    NSString *rekallPath = [[NSBundle mainBundle] pathForResource:@"rekal"
                                                           ofType:nil
                                                      inDirectory:@"rekal"];
    // Arguments:
    NSArray *rekallArgs = [NSArray arrayWithObjects:
                           @"-f", [path path], // image path
                           @"webconsole", // plugin name
                           @"--no_browser", // don't open Safari
                           nil];

    // Omitting the port number will cause rekall to bind a random available port.
    // Supressing the browser will cause rekall to print the server address to stderr.
    // We create a pipe and a callback for any writes to stderr and try to find the port.
    // Until the port number is detected, self.port will be RKNullPortNumberSentinel.
    
    self.rekallStdErrString = [[NSMutableString alloc] init];
    
    // Set up a pipe for rekall to write standard error into, and attach a handler that'll
    // append everything to a buffer and pass it to tryExtractWebconsoleAddress.
    self.rekallStdErr = [NSPipe pipe];
    self.rekallStdErr.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = [handle availableData];
        NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
        if(self.port == RKNullPortNumberSentinel) {
            // We're still looking for the server port.
            [self.rekallStdErrString appendString:string];
        }
        
        // Pass this through to the actual stderr, in case anyone's reading it.
        NSLog(@"Rekall stderr output:\n%@", string);
        
        // Try and see if rekall has written a port number to stderr.
        [self tryExtractWebconsoleAddress];
    };
    
    self.rekallTask = [[NSTask alloc] init];
    self.rekallTask.launchPath = rekallPath;
    self.rekallTask.arguments = rekallArgs;
    self.rekallTask.standardError = self.rekallStdErr;
    
    [self.rekallTask launch];
     
    return YES;
}

- (void)stopRekallWebconsoleSession {
    self.port = RKNullPortNumberSentinel;
    [self.rekallTask terminate];
}

@end
