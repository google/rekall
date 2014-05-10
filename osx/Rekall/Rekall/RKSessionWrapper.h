//
//  RKSessionWrapper.h
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import <Foundation/Foundation.h>

extern const NSInteger RKNullPortNumberSentinel;

@interface RKSessionWrapper : NSObject

@property (assign, readonly, nonatomic) NSInteger port;
@property (copy, nonatomic) void (^onLaunchCallback)(void);

- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf;
- (void)stopRekallWebconsoleSession;

@end
