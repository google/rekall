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

- (void)loadWebconsole:(id)sender;

@end


@implementation RKDocument

@synthesize webView, rekall, rekallURL, spinner;

- (id)init {
    if(![super init]) {
        return nil;
    }
    
    return self;
}

- (void)windowControllerDidLoadNib:(NSWindowController *)windowController {
    [super windowControllerDidLoadNib:windowController];
    [self.spinner startAnimation:self];
}

- (void)loadWebconsole:(id)sender {
    self.rekallURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d", (int)self.rekall.port]];
    NSLog(@"Connecting to the Rekall webconsole at %@", self.rekallURL);
    [self.webView setMainFrameURL:[self.rekallURL absoluteString]];
    [self.spinner removeFromSuperview];
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
    
    __weak id weakSelf = self;
    self.rekall.onLaunchCallback = ^(void){
        // I get called when webconsole is done launching.
        NSLog(@"Rekall webconsole is done launching.");
        [weakSelf performSelectorOnMainThread:@selector(loadWebconsole:) withObject:nil waitUntilDone:NO];
    };
    
    if (![self.rekall startWebconsoleWithImage:url error:outError]) {
        return NO;
    }
    
    return YES;
}

@end
