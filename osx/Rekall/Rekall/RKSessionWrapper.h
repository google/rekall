//
//  RKSessionWrapper.h
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import <Foundation/Foundation.h>

extern const NSInteger RKNullPortNumberSentinel;
extern NSString *const RKErrorDomain;
extern NSString *const RKErrorTitle;
extern NSString *const RKErrorDescription;

#define RKSessionRekallError 500


@interface RKSessionWrapper : NSObject

@property (assign, readonly, nonatomic) NSInteger port;
@property (copy, nonatomic) void (^onLaunchCallback)(void);
@property (copy, nonatomic) void (^onErrorCallback)(NSError *error);

- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf;
- (void)stopRekallWebconsoleSession;

@end
