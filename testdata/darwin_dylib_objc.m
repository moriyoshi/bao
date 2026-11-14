// Fixture for Bao's Objective-C dylib support: a class adopting a protocol,
// +load in a class and a category, a subclass calling super, a category on a
// Foundation class, lookup by name and Foundation calls.
#import <Foundation/Foundation.h>

@protocol BaoGreeter
- (int)greet;
@end

static int loaded;

@interface BaoCounter : NSObject <BaoGreeter>
@property int count;
+ (instancetype)shared;
- (int)increment;
@end

@implementation BaoCounter
+ (void)load { loaded += 1; }
+ (instancetype)shared {
    static BaoCounter *shared;
    if (!shared) shared = [BaoCounter new];
    return shared;
}
- (int)increment { return ++_count; }
- (int)greet { return 7; }
@end

@interface BaoCounter (Twice)
- (int)incrementTwice;
@end

@implementation BaoCounter (Twice)
+ (void)load { loaded += 10; }
- (int)incrementTwice {
    [self increment];
    return [self increment];
}
@end

@interface BaoChild : BaoCounter
@end

@implementation BaoChild
- (int)increment { return [super increment] + 100; }
@end

@interface NSString (Bao)
- (int)baoLength;
@end

@implementation NSString (Bao)
- (int)baoLength { return (int)self.length * 2; }
@end

// out: +load count, category method, subclass via super, protocol method,
// category on NSString, lookup by name, Foundation formatting.
__attribute__((visibility("default"))) void objc_check(int *out) {
    @autoreleasepool {
        BaoCounter *c = [BaoCounter shared];
        out[0] = loaded;
        out[1] = [c incrementTwice];
        out[2] = [[BaoChild new] increment];
        out[3] = [c conformsToProtocol:@protocol(BaoGreeter)] ? [(id<BaoGreeter>)c greet] : -1;
        out[4] = [@"abc" baoLength];
        out[5] = NSClassFromString(@"BaoChild") == [BaoChild class];
        out[6] = [[NSString stringWithFormat:@"%d-%@", 42, @"x"] isEqualToString:@"42-x"];
    }
}
