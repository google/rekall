//
//  RKDocument.m
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import "RKDocument.h"
#import "RKSessionWrapper.h"

@interface RKDocument ()

@property (retain) RKSessionWrapper *rekall;
@property (retain) NSURL *rekallURL;
@property (retain) NSOperationQueue *queue;
@property (assign) NSInteger retryCount;

- (void)deferTryLoadingWebconsole:(id)userInfoOrNil;
- (void)tryLoadingWebconsole:(id)userInfoOrNil;

@end


@implementation RKDocument

@synthesize webView, rekall, queue, rekallURL, retryCount, spinner;

- (id)init {
    if(![super init]) {
        return nil;
    }
    
    self.queue = [[NSOperationQueue alloc] init];
    self.retryCount = 0;
    
    return self;
}

- (void)tryLoadingWebconsole:(id)userInfoOrNil {
    NSLog(@"Testing if rekall is reachable at %@ yet...", self.rekallURL);
    NSURLRequest *request = [NSURLRequest requestWithURL:self.rekallURL];
    
    [NSURLConnection sendAsynchronousRequest:request
                                       queue:self.queue
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
                               if(httpResponse.statusCode == 200) {
                                   NSLog(@"Rekall is reachable at %@. Using webview %@", self.rekallURL, self.webView);
                                   
                                   // Needs to run on the main thread.
                                   [self.webView performSelectorOnMainThread:@selector(setMainFrameURL:)
                                                                  withObject:[self.rekallURL absoluteString]
                                                               waitUntilDone:NO];
                                   [self.spinner removeFromSuperview];
                               } else {
                                   NSLog(@"Rekall is not reachable - retrying in 0.5 seconds.");
                                   [self performSelectorOnMainThread:@selector(deferTryLoadingWebconsole:)
                                                          withObject:nil
                                                       waitUntilDone:YES];
                               }
                           }];
}

- (void)windowControllerDidLoadNib:(NSWindowController *)windowController {
    [super windowControllerDidLoadNib:windowController];
    [self.spinner startAnimation:self];
}

- (void)deferTryLoadingWebconsole:(id)userInfoOrNil {
    if (self.retryCount >= 100){
        NSLog(@"Don't want to retry more than a 100 times. Terminating.");
        return;
    }
    
    self.retryCount++;
    [self performSelector:@selector(tryLoadingWebconsole:) withObject:nil afterDelay:0.5];
}

- (NSString *)windowNibName {
    return @"RKDocument";
}

+ (BOOL)autosavesInPlace {
    return YES;
}

- (void)close {
    NSLog(@"Terminating rekall instance at %@ because window closed.", self.rekallURL);
    [self.rekall stopRekallWebconsoleSession];
}

- (BOOL)readFromURL:(NSURL *)url ofType:(NSString *)typeName error:(NSError *__autoreleasing *)outError {
    NSLog(@"Launching a rekall instance for %@", url);
    self.rekall = [[RKSessionWrapper alloc] init];
    if (![self.rekall startWebconsoleWithImage:url error:outError]) {
        return NO;
    }
    
    self.rekallURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d", (int)self.rekall.port]];
    [self deferTryLoadingWebconsole:nil];
    
    return YES;
}

@end
