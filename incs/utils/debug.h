#ifndef DEBUG_H
#define DEBUG_H

#ifdef ENABLE_DEBUG
#define DEBUG(fmt , ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG(fmt , ...) do{}while(0)
#endif

#define WITH_DEBUG(enable) for (int _done = (enable); _done; _done = !_done)

#endif // DEBUG_H