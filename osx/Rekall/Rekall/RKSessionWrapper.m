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

static NSRegularExpression *RKWrapperPortRegex;
static NSRegularExpression *RKWrapperErrorRegex;

@interface RKSessionWrapper ()

@property (retain) NSTask *rekallTask;
@property (assign, readwrite) NSInteger port;

@property (retain) NSPipe *rekallStdErr;
@property (retain) NSMutableString *rekallStdErrString;

- (void)tryExtractWebconsoleAddress;

@end


@implementation RKSessionWrapper

@synthesize port, rekallTask, rekallStdErr, rekallStdErrString, onLaunchCallback, onErrorCallback;

+ (void)initialize {
    
}

- (void)tryExtractWebconsoleAddress {
    NSLog(@"Parsing rekall stderr output for errors and bind info.");
    
    if(!RKWrapperPortRegex) {
        RKWrapperErrorRegex = [NSRegularExpression regularExpressionWithPattern:RKWrapperErrorPattern
                                                                        options:NSRegularExpressionCaseInsensitive
                                                                          error:nil];
        RKWrapperPortRegex = [NSRegularExpression regularExpressionWithPattern:RKWrapperPortPattern
                                                                       options:NSRegularExpressionCaseInsensitive
                                                                         error:nil];
    }
    
    NSTextCheckingResult *match;
    
    // Any errors?
    match = [RKWrapperErrorRegex firstMatchInString:self.rekallStdErrString
                                           options:0
                                             range:(NSRange) {0, self.rekallStdErrString.length}];
    
    if(match) {
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
        
        return;
    }
    
    // Port number?
    match = [RKWrapperPortRegex firstMatchInString:self.rekallStdErrString
                                           options:0
                                             range:(NSRange) {0, self.rekallStdErrString.length}];
    
    if(!match) {
        return;
    }
    
    NSString *result = [self.rekallStdErrString substringWithRange:[match rangeAtIndex:1]];
    NSLog(@"Match found: %@", result);
    
    NSInteger scannedPortNumber;
    NSScanner *scanner = [NSScanner scannerWithString:result];
    [scanner scanInteger:&scannedPortNumber];
    self.port = scannedPortNumber;
    
    // Execute callback since we found the port number.
    if(self.onLaunchCallback) {
        self.onLaunchCallback();
    }
}

- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf {
    [self stopRekallWebconsoleSession];
    
    NSString *rekallPath = [[NSBundle mainBundle] pathForResource:@"rekal"
                                                           ofType:nil
                                                      inDirectory:@"rekal"];
    NSArray *rekallArgs = [NSArray arrayWithObjects:
                           @"-f", [path path],
                           @"webconsole",
                           @"--no_browser",
                           nil];

    // Omitting the port number will cause rekall to bind a random available port.
    // Supressing the browser will cause rekall to print the server address to stderr.
    // We create a pipe and a callback for any writes to stderr and try to find the port.
    // Until the port number is detected, self.port will be RKNullPortNumberSentinel.
    
    self.rekallStdErrString = [[NSMutableString alloc] init];
    self.port = RKNullPortNumberSentinel;
    
    self.rekallStdErr = [NSPipe pipe];
    self.rekallStdErr.fileHandleForReading.readabilityHandler = ^(NSFileHandle *handle) {
        NSData *data = [handle availableData];
        NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
        if(self.port == RKNullPortNumberSentinel) {
            // We're still looking for the server port.
            [self.rekallStdErrString appendString:string];
        }
        
        // Pass this through to the actual stderr.
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
    [self.rekallTask terminate];
}

@end
