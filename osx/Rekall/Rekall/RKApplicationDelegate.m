//
//  RKApplicationDelegate.m
//  Rekall
//
//  Created by Adam Sindelar on 5/10/14.
//  Copyright (c) 2014 Rekall. All rights reserved.
//

#import "RKApplicationDelegate.h"

@implementation RKApplicationDelegate

- (BOOL)applicationShouldOpenUntitledFile:(NSApplication *)sender {
    return NO;
}

@end
