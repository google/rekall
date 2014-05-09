//
//  RKSessionWrapper.m
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import "RKSessionWrapper.h"

static NSInteger availablePort = 4000;

@interface RKSessionWrapper ()

@property (retain) NSTask *rekallTask;
@property (assign, readwrite) NSInteger port;

@end


@implementation RKSessionWrapper

@synthesize port, rekallTask;

- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf {
    [self stopRekallWebconsoleSession];
    
    self.port = ++availablePort;
    
    NSString *rekallPath = [[NSBundle mainBundle] pathForResource:@"rekal"
                                                           ofType:nil
                                                           inDirectory:@"rekal"];
    NSArray *rekallArgs = [NSArray arrayWithObjects:
                           @"-f", [path path],
                           @"webconsole",
                           @"--port",
                           [NSString stringWithFormat:@"%d", (int)self.port],
                           @"--no_browser",
                           nil];
    
    self.rekallTask = [NSTask launchedTaskWithLaunchPath:rekallPath
                                               arguments:rekallArgs];
    return YES;
}

- (void)stopRekallWebconsoleSession {
    [self.rekallTask terminate];
}

@end
