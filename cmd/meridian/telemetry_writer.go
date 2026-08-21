package main

import (
	"errors"
	"fmt"
	"log"
	"time"
)

var errDynamicObservationWriterClosed = errors.New("dynamic observation writer is closed")

type queuedDynamicObservation struct {
	event        dynamicObservationEvent
	stage        string
	observedAtMS int64
}

type dynamicObservationCommandKind uint8

const (
	dynamicObservationCommandWrite dynamicObservationCommandKind = iota
	dynamicObservationCommandRequestLogWrite
	dynamicObservationCommandFlush
	dynamicObservationCommandClear
	dynamicObservationCommandRequestLogClear
	dynamicObservationCommandStop
)

type dynamicObservationCommand struct {
	kind       dynamicObservationCommandKind
	event      queuedDynamicObservation
	requestLog queuedRequestLog
	siteID     int64
	result     chan error
}

func (d *DB) sendDynamicObservationControl(kind dynamicObservationCommandKind, siteID int64) error {
	if d == nil {
		return errDynamicObservationWriterClosed
	}
	result := make(chan error, 1)
	command := dynamicObservationCommand{kind: kind, siteID: siteID, result: result}
	d.dynamicObservationGate.RLock()
	if d.dynamicObservationClosed.Load() || d.dynamicObservationQueue == nil {
		d.dynamicObservationGate.RUnlock()
		return errDynamicObservationWriterClosed
	}
	d.dynamicObservationQueue <- command
	d.dynamicObservationGate.RUnlock()
	return <-result
}

func (d *DB) flushDynamicObservations() error {
	return d.sendDynamicObservationControl(dynamicObservationCommandFlush, 0)
}

func (d *DB) runDynamicObservationWriter() {
	defer close(d.dynamicObservationDone)
	ticker := time.NewTicker(dynamicObservationMaintenanceInterval)
	defer ticker.Stop()

	batch := make([]queuedDynamicObservation, 0, dynamicObservationBatchSize)
	requestBatch := make([]queuedRequestLog, 0, requestLogBatchSize)
	var pending dynamicObservationCommand
	hasPending := false
	for {
		var command dynamicObservationCommand
		if hasPending {
			command = pending
			hasPending = false
		} else {
			select {
			case command = <-d.dynamicObservationQueue:
			case <-ticker.C:
				if err := d.pruneDynamicObservations(); err != nil {
					d.droppedDynamicObservations.Add(1)
					log.Printf("[dynamic-observations] optional retention write failed: %v", err)
				}
				if err := d.pruneRequestLogs(); err != nil {
					d.droppedRequestLogs.Add(1)
					log.Printf("[request-logs] optional retention write failed: %v", err)
				}
				continue
			}
		}

		if command.kind == dynamicObservationCommandWrite {
			batch = batch[:0]
			batch = append(batch, command.event)
		drainBatch:
			for len(batch) < dynamicObservationBatchSize {
				select {
				case next := <-d.dynamicObservationQueue:
					if next.kind != dynamicObservationCommandWrite {
						pending = next
						hasPending = true
						break drainBatch
					}
					batch = append(batch, next.event)
				default:
					break drainBatch
				}
			}
			skipped, err := d.writeDynamicObservationBatch(batch)
			if err != nil {
				d.droppedDynamicObservations.Add(uint64(len(batch)))
				log.Printf("[dynamic-observations] optional batch write failed: %v", err)
			} else if skipped > 0 {
				d.droppedDynamicObservations.Add(uint64(skipped))
			}
			continue
		}
		if command.kind == dynamicObservationCommandRequestLogWrite {
			requestSettings := d.currentSystemSettings()
			requestBatchLimit := requestSettings.LogBatchSize
			if requestBatchLimit < 1 || requestBatchLimit > requestLogBatchSize {
				requestBatchLimit = requestLogBatchSize
			}
			requestBatch = requestBatch[:0]
			requestBatch = append(requestBatch, command.requestLog)
		drainRequestBatch:
			for len(requestBatch) < requestBatchLimit {
				select {
				case next := <-d.dynamicObservationQueue:
					if next.kind != dynamicObservationCommandRequestLogWrite {
						pending = next
						hasPending = true
						break drainRequestBatch
					}
					requestBatch = append(requestBatch, next.requestLog)
				default:
					break drainRequestBatch
				}
			}
			skipped, err := d.writeRequestLogBatch(requestBatch)
			for attempt := 0; err != nil && attempt < requestSettings.LogRetryCount; attempt++ {
				time.Sleep(time.Duration(requestSettings.LogRetryBackoffMS) * time.Millisecond)
				skipped, err = d.writeRequestLogBatch(requestBatch)
			}
			if err != nil {
				d.droppedRequestLogs.Add(uint64(len(requestBatch)))
				log.Printf("[request-logs] optional batch write failed: %v", err)
			} else if skipped > 0 {
				d.droppedRequestLogs.Add(uint64(skipped))
			}
			continue
		}

		switch command.kind {
		case dynamicObservationCommandFlush:
			command.result <- nil
		case dynamicObservationCommandClear:
			_, err := d.db.Exec("DELETE FROM dynamic_observations WHERE site_id=?", command.siteID)
			command.result <- err
		case dynamicObservationCommandRequestLogClear:
			_, err := d.db.Exec("DELETE FROM request_logs")
			command.result <- err
		case dynamicObservationCommandStop:
			command.result <- nil
			return
		default:
			if command.result != nil {
				command.result <- fmt.Errorf("unknown dynamic observation command")
			}
		}
	}
}
