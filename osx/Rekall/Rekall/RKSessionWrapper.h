//
//  RKSessionWrapper.h
//  Rekall
//
//  Created by Adam Sindelar on 5/8/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RKSessionWrapper : NSObject

@property (assign, readonly) NSInteger port;

- (BOOL)startWebconsoleWithImage:(NSURL *)path error:(NSError **)errorBuf;
- (void)stopRekallWebconsoleSession;

@end
