#!/usr/bin/tclsh

#--------------------------------------
# iTrack 1.0 alpha
# IDS System based on tcpdump analysis
# Steven W. Balch Jr.
#--------------------------------------

set conffile [lindex $argv 0]

#--------------------------------------

#--------------------------------------
if {$conffile == ""} {
puts {}
puts { -- It looks like you missed one command line argument -- }
puts {}
puts {  -- iTrack / v1.0 alpha / IDS System Based on tcpdump analysis -- }
puts {}
puts {      -- This is how you use this utility -- }
puts {}
puts {      -- ./iTrack.tcl iTrack.conf -- }
puts {}
exit
                    }

puts ""
puts "Starting iTrack...."
puts ""
#--------------------------------------

#--------------------------------------
# set some basic variables
set date [exec date +%d%b%Y-%T]

set activef active.bin
set collectf collect.bin
exec touch collect.bin
exec rm collect.bin
exec touch collect.bin

#--------------------------------------

#--------------------------------------
proc getconf {} {
global conffile include interface output
set confinfo [open $conffile r]
set incrl include

while {[gets $confinfo entry] >= 0} {


if {[regexp {interface:} $entry] ==1} {
set spline_1 [split $entry {:}]
set interface [lindex $spline_1 1]
                                      }

if {[regexp {include:} $entry] ==1} {
set spline_1 [split $entry {:}]
set inc [lindex $spline_1 0]

if {[string compare $incrl $inc] == 1} {
set bpf [lindex $spline_1 1]

} else {
set bpf [lindex $spline_1 1]
set include($bpf) 1
       }

                                    }

                                    }

close $confinfo
                  }

#--------------------------------------

#--------------------------------------
proc background {} {
global conffile activef collectf interface
exec /bin/bash -c "tcpdump -i $interface -s 1514 -U -w $activef > /dev/null &"
after 5000
catch {exec ps -e | grep tcpdump} result
if {[regexp "tcpdump" $result] == 1 } {
set result2 [string trim $result]
set result3 [split $result2 ]
set psfield [lindex $result3 0]
exec kill $psfield
exec cp $activef $collectf
                                      }
parsebin
background
                   }

#--------------------------------------

#--------------------------------------
proc parsebin {} {
global include output collectf

set date [exec date +%d%b%Y]
set trash "reading from file collect.bin"

set includerw [array get include]

foreach {item val} $includerw {
set filteritem $item
catch {exec /bin/bash -c "tcpdump -U -vvv -X -s 1514 -n -r $collectf -F filters/$item"} result01

#puts [string length $result01]
#puts $result01

if {[string length $result01] == 58} {
set $result01 {}
} else {

if {[string length $result01] == 0} {
} else {

#puts $result01
puts ""
puts "Detection(s) of '$item':"
puts ""

set result02 [split $result01 \n]
foreach line $result02 {

if {[regexp $trash $line] == 1} {
} else {
puts $line

       }

                       }
       }
       }
                              }
               }
#--------------------------------------

#--------------------------------------
# Run procdures
getconf
background
#--------------------------------------

#--------------------------------------
