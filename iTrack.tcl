#!/usr/bin/tclsh

#--------------------------------------
# iTrack 1.0 alpha
# IDS System based on tcpdump analysis
# Steven W. Balch Jr.
#--------------------------------------

set Tnm 1

if [catch {package require Tnm} err] {
puts {}
puts { -- It appears you do not have Tnm installed -- }
puts {}
puts {  -- iTrack / v1.0 alpha / IDS System Based on tcpdump analysis -- }
puts {}
puts {      -- I will NOT be able to send data to syslog -- }
puts {}
puts {      -- I will be sending the date to console instead -- }
puts {}
set Tnm 0
                                     }

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
puts {      -- ./itrack.tcl configuration-file -- }
puts {}
puts {      -- for example -- }
puts {}
puts {      -- ./itrack.tcl itrack.conf > /dev/null & -- }
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

set activef .active.bin
set collectf .collect.bin
exec touch .collect.bin
exec rm .collect.bin
exec touch .collect.bin

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

if {[regexp {output:} $entry] ==1} {
set spline_1 [split $entry {:}]
set output [lindex $spline_1 1]
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
exec tcpdump -i $interface -s 1514 -w $activef &
after 25000
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
global include output collectf Tnm

set date [exec date +%d%b%Y]

set includerw [array get include]

foreach {item val} $includerw {
set filteritem $item
catch {exec tcpdump -vv -s 1514 -n -r $collectf -F filters/$item} result01


if {[string length $result01] == 0} {
} else {

set result02 [split $result01 \n]
foreach line $result02 {


if {$Tnm == 0} {
if {[regexp syslog $output] == 1 } {
exec echo "Packet match with $filteritem ~ $line" >> $date.log
puts "Packet match with $filteritem ~ $line"
                                   }
               }

if {[regexp console $output] == 1 } {
puts "Packet match with $filteritem ~ $line"
exec echo "Packet match with $filteritem ~ $line" >> $date.log
                                    }

if {$Tnm == 1} {
if {[regexp syslog $output] == 1 } {
syslog info "Packet match with $filteritem ~ $line"
exec echo "Packet match with $filteritem ~ $line" >> $date.log
               }

} else {
puts "Packet match with $filteritem ~ $line"
exec echo "Packet match with $filteritem ~ $line" >> $date.log
       }
                        }

       }
#--------------------------------------
                                } 
                   }
#--------------------------------------

#--------------------------------------
# Run procdures
getconf
parsebin
background
#--------------------------------------

#--------------------------------------
