#!/usr/bin/python
import random

# Simulate a SYN-ACK sequence selector, and various ACK guessing methods



def init():
    global seq, guess, seq_incr, guess_range, guess_range_base
    seq = random.randint(0, 2**32)  # starting offset for the target
    seq_incr = 1035744715           # the amount the seq increases per period
    
    guess = 0
    guess_range_base = 14182561          # number of ports we can guess per period
    guess_range = guess_range_base

def update_round():
    global guess, seq, guess_range, seq_incr, guess_range_base
    

    seq += seq_incr + random.randint(-1000000, 1000000)
    guess += guess_range
    guess += seq_incr
    guess_range = guess_range_base + random.randint(-100000, 100000)

    seq %= 2**32
    guess %= 2**32
    

wins = []

for x in range(10000):
    rounds = 0
    init()

    while 1:
        if guess <= seq < (guess + guess_range):
            #print 'Win after %d rounds' % rounds
            wins.append(rounds)
            break

        update_round()
        rounds += 1
   
wins.sort()
print 'average: %f' % (sum(wins)/float(len(wins)))
print 'median: %d' % wins[len(wins)/2]
print 'range: %d-%d' % (wins[0], wins[-1])


