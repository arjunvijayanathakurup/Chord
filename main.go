package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The m bit from the paper, meaning a possible of 2^m nodes can be in the system The number of bits from the paper meaning the number of nodes in the system 2^m
const BITS_SIZE_RING = 160

// Constants for RSA encryption
const (
	LABEL                           = "content"
	ENCRYPTION_PUBLIC_KEY_PATH      = "./keys/encryption-pub.pem"
	AUTHENTICATION_PUBLIC_KEY_PATH  = "./keys/id_rsa.pub"
	AUTHENTICATION_PRIVATE_KEY_PATH = "./keys/id_rsa"
)

// Constants for SFTP
const (
	USER = "foo"
)

// File constanst
const (
	FOLDER_RESOURCES = "./resources"
	PERMISSIONS_FILE = 0o600
	PERMISSIONS_DIR  = 0o700
)

// rpctypes
type SuccessorRep struct {
	Successors []NodeInfo
}
type PredecessorRep struct {
	Predecessor *NodeInfo
}
type StoreFileArgs struct {
	Key     big.Int
	Content []byte
}

type TransferFileArgs struct {
	Files map[string]*[]byte
}
type FindSuccessorRep struct {
	Found bool
	Node  NodeInfo
}
type NodeAddress string

type Key string

type NodeInfo struct {
	IpAddress  string
	ChordPort  int
	SshPort    int
	Identifier big.Int
}

type Node struct {
	Info            NodeInfo
	FingerTable     []NodeInfo
	FingerTableSize int
	Predecessor     *NodeInfo
	Successors      []NodeInfo
	SuccessorsSize  int
	NextFinger      int
}

func main() {

	// Reading the flags
	var f Flags
	var errFlags = InitFlags(&f)
	if errFlags != nil {
		fmt.Printf("Flag reading error" + errFlags.Error())
		return
	}

	// Chord Ring Creation
	var NewRingcreate = f.CreateNewRingSet()
	var additionalIdetifier = f.GetAdditionaIIdentifier()
	var additionalIdetifierBigInt *big.Int = nil
	if additionalIdetifier != nil {
		var res, errOptionalIdentifier = ConvertHexString(*additionalIdetifier)
		if errOptionalIdentifier != nil {
			// fmt.Printf("Optional Identifier converting error" + errOptionalIdentifier.Error())
			return
		}
		additionalIdetifierBigInt = res
	}

	var errChord = Start(f.IpAddress, f.ChordPort, f.SshPort, BITS_SIZE_RING, f.SuccessorLimit, NewRingcreate, &f.JoinIpAddress, &f.JoinPort, additionalIdetifierBigInt)
	if errChord != nil {
		fmt.Printf("Chord Node initialization error " + errChord.Error())
		return
	}

	var nodeKey = Get().Info.Identifier
	InitNodeFileSystem(nodeKey.String())

	// Server Initialization
	var listener, errListener = net.Listen("tcp", ":"+fmt.Sprintf("%v", f.ChordPort))
	if errListener != nil {
		fmt.Printf("Listening Socket Initialization error " + errListener.Error())
		return
	}
	RpcServerInit(&listener)

	// Scheduling tasks for stabilize, fix fingers, check predecessor and FileBackup
	Schedule(Stabilize, time.Duration(f.TimeStabilize*int(time.Millisecond)))
	Schedule(FixFingers, time.Duration(f.TimeFixFingers*int(time.Millisecond)))
	Schedule(CheckPredecessor, time.Duration(f.TimeCheckPredecessor*int(time.Millisecond)))
	Schedule(FileBackup, time.Duration(f.TimeBackup*int(time.Millisecond)))

	// Requesting for User Input
	CommandsExecution()
}

// All member variables need to be capitalized for them to be accessible outside the package
type Flags struct {
	IpAddress            string
	ChordPort            int
	SshPort              int
	JoinIpAddress        string
	JoinPort             int
	TimeStabilize        int
	TimeFixFingers       int
	TimeCheckPredecessor int
	TimeBackup           int
	SuccessorLimit       int
	identifierOverride   string
}

const (
	INVALID_STRING = "NOT_VALID"
	INVALID_INT    = -1
)

func InitFlags(f *Flags) error {
	//Placeholder default value as item must be specified
	flag.StringVar(&f.IpAddress, "a", INVALID_STRING, "The IP address that the Chord client will bind to, as well as advertise to other nodes. Represented as an ASCII string (e.g., 128.8.126.63). Must be specified.")
	flag.IntVar(&f.ChordPort, "p", INVALID_INT, "The port that the Chord client will bind to and listen on. Represented as a base-10 integer. Must be specified.")
	flag.IntVar(&f.SshPort, "sp", INVALID_INT, "The port number for the SSH server. Must be specidfied")
	flag.StringVar(&f.JoinIpAddress, "ja", INVALID_STRING, "The IP address of the machine running a Chord node. The Chord client will join this nodes ring. Represented as an ASCII string (e.g., 128.8.126.63). Must be specified if --jp is specified.")
	flag.IntVar(&f.JoinPort, "jp", INVALID_INT, "The port that an existing Chord node is bound to and listening on. The Chord client will join this nodes ring. Represented as a base-10 integer. Must be specified if --ja is specified.")
	flag.IntVar(&f.TimeStabilize, "ts", INVALID_INT, "The port that an existing Chord node is bound to and listening on. The Chord client will join this nodes ring. Represented as a base-10 integer. Must be specified if --ja is specified.")
	flag.IntVar(&f.TimeFixFingers, "tff", INVALID_INT, "The port that an existing Chord node is bound to and listening on. The Chord client will join this nodes ring. Represented as a base-10 integer. Must be specified if --ja is specified.")
	flag.IntVar(&f.TimeCheckPredecessor, "tcp", INVALID_INT, "The time in milliseconds between invocations of check predecessor.")
	flag.IntVar(&f.TimeBackup, "tb", INVALID_INT, "The time duration for backup interval.Must be specified")
	flag.IntVar(&f.SuccessorLimit, "r", INVALID_INT, "The number of successors maintained by the Chord client. Represented as a base-10 integer. Must be specified, with a value in the range of [1,32].")
	flag.StringVar(&f.identifierOverride, "i", INVALID_STRING, "The identifier (ID) assigned to the Chord client which will override the ID computed by the SHA1 sum of the client’s IP address and port number. Represented as a string of 40 characters matching [0-9a-fA-F]. Optional parameter.")
	flag.Parse()
	return FlagsValidation(f)
}

func RangeFlagValidation(f, startRange, endRange int) bool {
	return startRange <= f && f <= endRange
}

func ErrorMessageCreation(flagname, description string) string {
	return fmt.Sprintf("Set %v: %v\n", flagname, description)
}

func FlagsValidation(f *Flags) error {
	var errorString = ""
	if f.IpAddress == INVALID_STRING {
		errorString += ErrorMessageCreation("-a", "IP Address Binding error")
	}
	if f.ChordPort == INVALID_INT {
		errorString += ErrorMessageCreation("-p", "Port number Error")
	}
	if f.SshPort == INVALID_INT {
		errorString += ErrorMessageCreation("-sp", "SSH server port number error")
	}
	if (f.JoinIpAddress == INVALID_STRING && f.JoinPort != INVALID_INT) || (f.JoinIpAddress != INVALID_STRING && f.JoinPort == INVALID_INT) {
		var flagname string
		if f.JoinIpAddress == INVALID_STRING {
			flagname = "--ja"
		} else {
			flagname = "--jp"
		}
		errorString += ErrorMessageCreation(flagname, "Both -ja and -jp needs to specified")
	}
	if !RangeFlagValidation(f.TimeStabilize, 1, 60000) {
		errorString += ErrorMessageCreation("--ts", "stabilize call, range [1, 60000]")
	}
	if !RangeFlagValidation(f.TimeFixFingers, 1, 60000) {
		errorString += ErrorMessageCreation("--tff", "fix fingers call, range [1, 60000]")
	}
	if !RangeFlagValidation(f.TimeCheckPredecessor, 1, 60000) {
		errorString += ErrorMessageCreation("--tcp", "check predecessor call, range [1, 60000]")
	}
	if !RangeFlagValidation(f.TimeBackup, 1, 60000) {
		errorString += ErrorMessageCreation("--tcp", " run backup files call, range [1, 60000]")
	}
	if !RangeFlagValidation(f.SuccessorLimit, 1, 32) {
		errorString += ErrorMessageCreation("-r", "successors should be in range [1, 32]")
	}
	if f.identifierOverride != INVALID_STRING {
		var noOfChars = BITS_SIZE_RING / 4
		var _, err = hex.DecodeString(f.identifierOverride)
		if err != nil || noOfChars != len(f.identifierOverride) {
			errorString += ErrorMessageCreation("-i", fmt.Sprintf("hexadecimal should be in values: [0-9][a-f][A-F], number of values: %v", noOfChars))
		}
	}
	if errorString == "" {
		return nil
	}
	return errors.New(errorString)
}

func (flag Flags) GetAdditionaIIdentifier() *string {
	if flag.identifierOverride == INVALID_STRING {
		return nil
	}
	return &flag.identifierOverride
}

func (flag Flags) CreateNewRingSet() bool {
	return flag.JoinIpAddress == INVALID_STRING && flag.JoinPort == INVALID_INT
}

func Lookup(fileKey big.Int) (*NodeInfo, error) {
	var n = Get()
	var node, errFind = find(fileKey, n.Info, 32)
	if errFind != nil {
		return nil, errFind
	}
	return node, nil
}

func StoreFile(filePath string, ssh bool, encrypted bool) (*NodeInfo, *big.Int, error) {
	var fileName = GetFileName(filePath)
	var fileKey = Hash(fileName)
	var node, errLookup = Lookup(*fileKey)
	if errLookup != nil {
		return nil, nil, errLookup
	}
	var content, errRead = ReadFile(filePath)
	if errRead != nil {
		return nil, nil, errRead
	}
	if encrypted {
		var encrypted, errEncryption = Encryption(content)
		if errEncryption != nil {
			return nil, nil, errEncryption
		}
		content = encrypted
	}
	// fmt.Printf("File Storing at %v", *node)
	if ssh {
		var fileName = fileKey.String()
		var errSftp = FileSending(ObtainSshAddress(*node), fileName, content)
		if errSftp != nil {
			return nil, nil, errSftp
		}
	} else {
		var errRpc = StoreFileClient(ObtainChordAddress(*node), *fileKey, content)
		if errRpc != nil {
			return nil, nil, errRpc
		}
	}

	return node, fileKey, nil
}

func ObtainNodeState(node NodeInfo, collectionItem bool, index int, idealIdentifier *big.Int) (*string, error) {
	var nodeInfo = fmt.Sprintf("\nNode Identifier: %v\nNode IP address: %v | Chord Node Port Number: %v | SSH Server Port Number: %v", node.Identifier.String(), node.IpAddress, node.ChordPort, node.SshPort)
	if collectionItem {
		nodeInfo += fmt.Sprintf("\nNode Index Value: %v | Node Index Identifier: %v", index, idealIdentifier)
	}
	nodeInfo += "\n"
	return &nodeInfo, nil
}

type CalculatePossibleIdentifier func(int) big.Int

func ObtainNodeArrayState(nodes []NodeInfo, calculatePossibleIdentifier CalculatePossibleIdentifier) (*string, error) {
	var state = new(string)
	for index, item := range nodes {
		var idealIdentifier = calculatePossibleIdentifier(index)
		var info, err = ObtainNodeState(item, true, index, &idealIdentifier)
		if err != nil {
			return nil, err
		}
		*state += *info + "\n\n"
	}
	return state, nil
}
func ObtainState() (*string, error) {
	var n = Get()
	var state, err = ObtainNodeState(n.Info, false, -1, nil)
	if err != nil {
		return nil, err
	}
	*state += "NodePredecessor: "
	if n.Predecessor == nil {
		*state += "None \n"
	} else {
		*state += n.Predecessor.Identifier.String()
	}

	*state += "\n\nNodeSuccessors:\n"

	var successorStatus, successorErr = ObtainNodeArrayState(n.Successors, func(i int) big.Int { return *new(big.Int).Add(big.NewInt(int64(i+1)), &n.Info.Identifier) })
	if successorErr != nil {
		return nil, successorErr
	}
	if successorStatus == nil {
		*state += "No successors available\n"
	} else {
		*state += *successorStatus
	}

	*state += "\nNodeFingertable:\n"

	var fingerTableStatus, fingerTableErr = ObtainNodeArrayState(n.FingerTable, func(i int) big.Int { return *Jump(n.Info.Identifier, i) })
	if fingerTableErr != nil {
		return nil, fingerTableErr
	}
	if fingerTableStatus == nil {
		*state += "No finger table entries available\n"
	} else {
		*state += *fingerTableStatus
	}
	return state, nil
}
func FindSuccessor(id big.Int) (bool, NodeInfo) {
	var n = Get()
	if Between(&n.Info.Identifier, &id, &n.Successors[0].Identifier, true) {
		// fmt.Printf("[findSuccessor] Nodeid: %v, return value: %v, %v", id, true, n.Successors[0])
		return true, n.Successors[0]
	}
	var NearestNode = NearestPrecedingNode(id)
	// fmt.Printf("[findSuccessor] Nodeid: %v, return value: %v, %v", id, false, NearestNode)
	return false, NearestNode
}
func find(id big.Int, start NodeInfo, maxSteps int) (*NodeInfo, error) {
	var found = false
	var nextNode = start
	for i := 0; i < maxSteps; i++ {
		var res, err = ClientLocateSuccessor(ObtainChordAddress(nextNode), &id)
		if err != nil {
			return nil, err
		}
		found = res.Found
		if found {
			return &res.Node, nil
		}
		nextNode = res.Node
	}
	return nil, errors.New("Successors Could not be found")
}

func locateNearestPrecedingCandidate(n Node, table []NodeInfo, id big.Int) *NodeInfo {
	for i := len(table) - 1; i >= 0; i-- {
		if Between(&n.Info.Identifier, &table[i].Identifier, &id, false) {
			return &table[i]
		}
	}
	return nil
}

func NearestPrecedingNode(id big.Int) NodeInfo {
	var n = Get()
	var candidate *NodeInfo = locateNearestPrecedingCandidate(n, n.FingerTable, id)
	if c := locateNearestPrecedingCandidate(n, n.Successors, id); candidate == nil || (c != nil &&
		Between(&id, &c.Identifier, &candidate.Identifier, false)) {
		candidate = c
	}
	if candidate != nil {
		// fmt.Printf("[NearestPrecedingNode] Nodeid: %v, return value: %v\n", id, *candidate)
		return *candidate
	}
	// fmt.Printf("[NearestPrecedingNode] Nodeid: %v, return value: %v\n", id, n.Info)
	return n.Info
}

func Start(ipAddress string, chordPort, sshPort, fingerTableSize, successorsSize int, NewRingcreate bool, joinIpAddress *string, joinPort *int, additionalIdetifier *big.Int) error {
	fmt.Printf("Beginning Chord Node at %v:%v with SSHServer on port: %v", ipAddress, chordPort, sshPort)
	// Sets predecessor to nil
	var err = NodeInstanceInit(ipAddress, chordPort, sshPort, fingerTableSize, successorsSize, additionalIdetifier)
	if err != nil {
		return err
	}
	if NewRingcreate {
		create()
		return nil
	}
	if joinIpAddress == nil || joinPort == nil {
		return errors.New("Joining ip address and port number required when NewRingcreate is set to false")
	}
	var temp = Get().Info.Identifier
	return join(*joinIpAddress, *joinPort, &temp, fingerTableSize)
}
func create() {
	NewSuccessor(Get().Info)
	NewFingerTable(Get().Info)
}

func join(joinIpAddress string, joinPort int, nodeId *big.Int, maxSteps int) error {
	var joinHash = big.NewInt(-1)
	var sshPort = -1

	var successor, errFind = find(*nodeId, NodeInfo{IpAddress: joinIpAddress, ChordPort: joinPort, SshPort: sshPort, Identifier: *joinHash}, maxSteps)
	if errFind != nil {
		return errFind
	}
	NewSuccessor(*successor)
	NewFingerTable(*successor)
	return nil
}
func Leave(n *Node) {

}

func Stabilize() {
	var x *NodeInfo
	var successorIndex = -1
	var n = Get()
	for index, item := range n.Successors {
		var err error
		x, err = Predecessor(ObtainChordAddress(item))
		// fmt.Printf("[chordFunctions.Stabilize] NodePredecessor is %v, err: %v, NodeIndex: %v", x, err, index)
		if err == nil {
			successorIndex = index
			break
		}
	}
	if x != nil && Between(&n.Info.Identifier, &x.Identifier, &n.Successors[successorIndex].Identifier, false) {
		NewSuccessor(*x)
	} else if x != nil {
	} else {

		NewSuccessor(n.Info)
	}
	if NoOfSuccessors() > 0 {

		var errNotify = ClientNotification(ObtainChordAddress(Successor()), n.Info)
		if errNotify != nil {
			fmt.Printf("[stabilze] Error found while notifying successor %v, message: %v", Successor(), errNotify.Error())
		}

		var successors, errSuc = Successors(ObtainChordAddress(Successor()))
		if errSuc == nil {

			AddSuccessors(successors)
		} else {
			fmt.Printf("[stabilize] Error found while fetching node successors from successor %v, message: %v", Successor(), errSuc.Error())
		}
	}
	// fmt.Printf("[stabilize] Successor List updated with new Successor as %v, new length is %v", n.Successors[0], len(n.Successors))
}

func Notify(node NodeInfo) {
	var n = Get()

	if n.Predecessor == nil || n.Predecessor.Identifier.Cmp(&n.Info.Identifier) == 0 ||
		Between(&n.Predecessor.Identifier, &node.Identifier, &n.Info.Identifier, false) {
		DefinePredecessor(&node)
	}
}

func FixFingers() {
	var next = NextFingerUpdation()
	// fmt.Printf("[fixFingers] next: %v", next)
	var n = Get()
	var identifierToFix = *Jump(n.Info.Identifier, next)
	var node, err = find(identifierToFix, n.Info, 32)
	if err != nil {
		// fmt.Printf("[fixFingers] Error observed while configuring finger table index %v equating the identifier %v+2^(%v)=%v. errmsg: %v\n", next, n.Info.Identifier, next, identifierToFix, err.Error())
		return
	}
	DefineFingerTableIndex(next, *node)
}

func CheckPredecessor() {
	var n = Get()
	if n.Predecessor != nil && !CheckAlive(ObtainChordAddress(*n.Predecessor)) {
		DefinePredecessor(nil)
		// fmt.Printf("[checkPredecessor] Node Predecessor set to nil as previous Node Predecessorr %v was not responsive\n", n.Predecessor)
	}
}

func ObtainMissingFiles(successors []NodeInfo, files []string) [][]string {
	var unavailableFiles [][]string
	var wg = new(sync.WaitGroup)
	wg.Add(len(successors))
	for _, successor := range successors {
		go func(address NodeAddress) {
			var rep, err = MissingFiles(address, files)
			if err != nil {
				unavailableFiles = append(unavailableFiles, []string{})
			} else {
				unavailableFiles = append(unavailableFiles, rep)
			}
			wg.Done()
		}(ObtainChordAddress(successor))
	}
	wg.Wait()
	return unavailableFiles
}
func filterAvailableFiles(files []string, predecessorIdentifier big.Int, nodeIdentifier big.Int) []string {
	var f = []string{}
	for _, item := range files {
		var temp = new(big.Int)
		var fileIdentifier, ok = temp.SetString(item, 10)
		// fmt.Printf("[chordFunctions.filterAvailableFiles] converting %v to %v with confirmation as: %v\n", item, fileIdentifier, ok)
		if ok && !Between(fileIdentifier, &predecessorIdentifier, &nodeIdentifier, false) {
			f = append(f, item)
		}
	}
	return f
}

func FileBackup() {
	var n = Get()
	if n.Predecessor == nil {
		return
	}

	// fmt.Printf("[chordFunctions.FileBackup] Requested")
	ObtainRWLock(false)
	// fmt.Printf("[chordFunctions.FileBackup] ReadWrite lock obtained ")

	var successors = n.Successors
	var nodeKey = n.Info.Identifier.String()
	var f, err = ListFiles(nodeKey)

	var ownedFiles = filterAvailableFiles(f, n.Predecessor.Identifier, n.Info.Identifier)
	if err != nil || len(ownedFiles) <= 0 || len(n.Successors) <= 0 {
		LiberateRWLock(false)
		return
	}
	fmt.Printf("[chordFunctions.FileBackup] Available Files in the system: %v\n", ownedFiles)

	var unavailableFiles = ObtainMissingFiles(successors, ownedFiles)
	var fls = NodeFilesRead(nodeKey, ownedFiles)
	fmt.Printf("[chordFunctions.FileBackup] Files Missing for Successors: %v\n", unavailableFiles)
	var wg = new(sync.WaitGroup)
	wg.Add(len(successors))
	for index, item := range successors {
		go func(i int, node NodeInfo) {
			var filesToTransfer = map[string]*[]byte{}
			for _, missingFile := range unavailableFiles[i] {
				var file, ok = fls[missingFile]
				if ok {
					filesToTransfer[missingFile] = file
				}
			}
			if len(filesToTransfer) > 0 {
				FileTransfer(ObtainChordAddress(node), filesToTransfer)
			}
			wg.Done()
		}(index, item)
	}
	wg.Wait()

	LiberateRWLock(false)
}

var once sync.Once

var instance Node

func NodeInstanceInit(ipAddress string, chordPort, sshPort, fingerTableSize, successorsSize int, additionalIdetifier *big.Int) error {
	if fingerTableSize < 1 || successorsSize < 1 {
		return errors.New("The Size needs to be atleast 1")
	}
	once.Do(func() {
		var address = NodeAddress(ipAddress) + ":" + NodeAddress(fmt.Sprintf("%v", chordPort))
		var info NodeInfo
		if additionalIdetifier == nil {
			info = NodeInfo{
				IpAddress:  ipAddress,
				ChordPort:  chordPort,
				SshPort:    sshPort,
				Identifier: *Hash(string(address)),
			}
		} else {
			info = NodeInfo{
				IpAddress:  ipAddress,
				ChordPort:  chordPort,
				SshPort:    sshPort,
				Identifier: *additionalIdetifier,
			}
		}
		instance = Node{
			Info:            info,
			FingerTable:     []NodeInfo{},
			Predecessor:     nil,
			FingerTableSize: fingerTableSize,
			Successors:      []NodeInfo{},
			SuccessorsSize:  successorsSize,
			NextFinger:      -1,
		}
	})
	return nil
}

func ObtainChordAddress(node NodeInfo) NodeAddress {
	return NodeAddress(fmt.Sprintf("%v:%v", node.IpAddress, node.ChordPort))
}

func ObtainSshAddress(node NodeInfo) string {
	return fmt.Sprintf("%v:%v", node.IpAddress, node.SshPort)
}

func NextFingerUpdation() int {
	instance.NextFinger = (instance.NextFinger + 1) % instance.FingerTableSize
	return instance.NextFinger
}

func NewSuccessor(successor NodeInfo) {
	instance.Successors = []NodeInfo{successor}
}

func NewFingerTable(successor NodeInfo) {
	instance.FingerTable = []NodeInfo{successor}
}

func SuccesorsContainsItself(successors []NodeInfo) int {
	for index, item := range successors {
		if item.Identifier.Cmp(&instance.Info.Identifier) == 0 {
			return index
		}
	}
	return -1
}

func AddSuccessors(successors []NodeInfo) {
	var noOfElementsToAdd = instance.SuccessorsSize - 1
	var elementsAddition []NodeInfo
	// In case the successors array is shorter than the amount of elements to add, the slicing would produce a kernel panic
	if len(successors) > noOfElementsToAdd {
		elementsAddition = successors[:noOfElementsToAdd]
	} else {
		elementsAddition = successors
	}
	var index = SuccesorsContainsItself(elementsAddition)
	if index != -1 {
		elementsAddition = elementsAddition[:index]
	}
	// fmt.Printf("Present successor is %v, new successors being added: %v\n", instance.Successors[0], elementsAddition)
	instance.Successors = append(instance.Successors, elementsAddition...)
}

// Returns the current successor
func Successor() NodeInfo {
	return instance.Successors[0]
}

func NoOfSuccessors() int {
	return len(instance.Successors)
}

// Set the index of an element if the previous index exists
// This is a simplification due to the fact that the FixFingers method
// adds elements to the list one at a time in an icreasing order.
func DefineFingerTableIndex(index int, item NodeInfo) error {
	if index >= instance.FingerTableSize || index > len(instance.FingerTable) {
		return errors.New("index above size, or element at index: " + fmt.Sprintf("%v", index-1) + " does not exist")
	}
	if index < len(instance.FingerTable) {
		instance.FingerTable[index] = item
		return nil
	}
	// Index == length of fingertable
	instance.FingerTable = append(instance.FingerTable, item)
	return nil
}

func DefinePredecessor(predecessor *NodeInfo) {
	instance.Predecessor = predecessor
}

func Get() Node {
	return instance
}

//commands.go

type Command struct {
	requiredParamers   int
	optionalParameters int
	usageString        string
}

func GetCommands() map[string]Command {
	return map[string]Command{
		"Lookup":     {1, 0, "usage: Lookup <filename>"},
		"l":          {1, 0, "usage: Lookup <filename>"},
		"StoreFile":  {1, 2, "usage: StoreFile <filepathOnDisk> [ssh: default=true, f or false to disable] encrypt file: default=true, f or false to disable]"},
		"s":          {1, 2, "usage: StoreFile <filepathOnDisk> [ssh: default=true, f or false to disable] [encrypt file: default=true, f or false to disable]"},
		"PrintState": {0, 0, "usage: PrintState"},
		"p":          {0, 0, "usage: PrintState"},
	}
}

func validateCommand(cmdArr []string) error {
	if len(cmdArr) <= 0 {
		return errors.New("Provide Command")
	}
	var cmd, ok = GetCommands()[cmdArr[0]]
	if !ok {
		return errors.New("Provided Command " + cmdArr[0] + " is not available")
	}
	if len(cmdArr)-1 < cmd.requiredParamers || len(cmdArr)-1 > cmd.optionalParameters+cmd.requiredParamers {
		return errors.New(cmd.usageString)
	}
	return nil
}

func ObtainTurnOffOption(cmdArr []string, index int) bool {
	if len(cmdArr) > index && (strings.ToLower(cmdArr[index]) == "false" || strings.ToLower(cmdArr[index]) == "f") {
		return false
	}
	return true
}

func CommandExecution(cmdArr []string) {
	switch cmdArr[0] {
	case "Lookup", "l":
		var answer, errLookup = Lookup(*Hash(cmdArr[1]))
		if errLookup != nil {
			fmt.Println(errLookup.Error())
			return
		}
		var state, errState = ObtainNodeState(*answer, false, -1, nil)
		if errState != nil {
			fmt.Println(errState.Error())
			return
		}
		fmt.Println(*state)
	case "StoreFile", "s":
		var ssh = ObtainTurnOffOption(cmdArr, 2)
		var encryption = ObtainTurnOffOption(cmdArr, 3)
		var node, fileKey, errStore = StoreFile(cmdArr[1], ssh, encryption)
		if errStore != nil {
			fmt.Println(errStore.Error())
			return
		}
		var state, errState = ObtainNodeState(*node, false, -1, nil)
		if errState != nil {
			fmt.Println(errState.Error())
			return
		}
		fmt.Printf("FileKey: %v\nStored at:\n%v\n", fileKey.String(), *state)
	case "PrintState", "p":
		var output, err = ObtainState()
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println(*output)
	default:
		fmt.Println("command is not available")
	}
}

func CommandsExecution() {
	var scanner = bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\nChord Node Prompt: ")
		var arguments, errRead = scanner.ReadString('\n')
		if errRead != nil {
			fmt.Println("Commands to be entered on a single line")
			continue
		}
		var cmdArr = strings.Fields(arguments)
		var errValidate = validateCommand(cmdArr)
		if errValidate != nil {
			fmt.Println(errValidate.Error())
			continue
		}
		CommandExecution(cmdArr)
	}
}

func Encryption(content []byte) ([]byte, error) {
	var pubKey, err = ObtainPubKey(ENCRYPTION_PUBLIC_KEY_PATH)
	if err != nil {
		return nil, err
	}
	var rand = rand.Reader
	return rsa.EncryptOAEP(sha256.New(), rand, pubKey, content, []byte(LABEL))
}

var lock = new(sync.RWMutex)

func ObtainRWLock(write bool) {
	if write {
		lock.Lock()
		return
	}
	lock.RLock()
}

func LiberateRWLock(write bool) {
	if write {
		lock.Unlock()
		return
	}
	lock.RUnlock()
}

func InitNodeFileSystem(nodeKey string) error {
	var folder = ObtainFileDir(nodeKey)
	var err = os.MkdirAll(folder, PERMISSIONS_DIR)
	if err != nil {
		return err
	}
	return nil
}

func ListFiles(nodeKey string) ([]string, error) {
	var dir, errReadDir = os.ReadDir(ObtainFileDir(nodeKey))
	if errReadDir != nil {
		fmt.Printf("[files.ListFiles] could not read the directory: %v\n", errReadDir)
		return nil, errReadDir
	}
	var files = []string{}
	for _, file := range dir {
		files = append(files, file.Name())
	}
	return files, nil
}

func GetFileName(filePath string) string {
	var paths = strings.Split(filePath, "/")
	return paths[len(paths)-1]
}

func ReadFile(filePath string) ([]byte, error) {
	var file, errRead = os.ReadFile(filePath)
	return file, errRead
}

func ReadNodeFile(nodeKey, fileKey string) ([]byte, error) {
	var file, errRead = os.ReadFile(ObtainFilePath(fileKey, nodeKey))
	return file, errRead
}

func NodeFilesRead(nodeKey string, filePaths []string) map[string]*[]byte {
	var files = make(map[string]*[]byte)
	for _, filePath := range filePaths {
		var content, err = ReadNodeFile(nodeKey, filePath)
		if err == nil {
			files[filePath] = &content
		}
	}
	return files
}

func ObtainFileDir(nodeKey string) string {
	return filepath.Join(FOLDER_RESOURCES, nodeKey)
}

func ObtainFilePath(key, nodeKey string) string {
	return filepath.Join(ObtainFileDir(nodeKey), key)
}

func NodeFileWrite(key, nodeKey string, content []byte) error {

	var folder = ObtainFileDir(nodeKey)
	var err = os.MkdirAll(folder, PERMISSIONS_DIR)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(folder, key), content, PERMISSIONS_FILE)
}

func NodeFilesWrite(nodeKey string, files map[string]*[]byte) []error {
	var folder = ObtainFileDir(nodeKey)
	var err = os.MkdirAll(folder, PERMISSIONS_DIR)
	if err != nil {
		return []error{err}
	}
	var errsWrite = []error{}
	for key, content := range files {
		var errWrite = os.WriteFile(ObtainFilePath(key, nodeKey), *content, PERMISSIONS_FILE)
		if errWrite != nil {
			errsWrite = append(errsWrite, errWrite)
		}
	}
	return errsWrite
}

func AddToFile(key, nodeKey string, content []byte) (int, error) {
	var file, errOpen = os.OpenFile(ObtainFilePath(key, nodeKey), os.O_APPEND|os.O_WRONLY, PERMISSIONS_FILE)
	if errOpen != nil {
		return 0, errOpen
	}
	defer file.Close()

	var num, errWrite = file.Write(content)
	if errWrite != nil {
		return num, errWrite
	}

	return num, nil
}

func DeleteFile(key, nodeKey string) {
	os.Remove(ObtainFilePath(key, nodeKey))
}

// identifier.go
func ConvertHexString(hexString string) (*big.Int, error) {
	var bytes, err = hex.DecodeString(hexString)
	if err != nil {
		return nil, err
	}
	var bigInt = new(big.Int)
	return bigInt.SetBytes(bytes), nil
}

const keySize = BITS_SIZE_RING

var two = big.NewInt(2)
var hashMod = new(big.Int).Exp(two, big.NewInt(keySize), nil)

func HashBytes(b []byte) *big.Int {
	var hasher = sha1.New()
	hasher.Write(b)
	var bytes = hasher.Sum(nil)
	return new(big.Int).SetBytes(bytes)
}

func Hash(elt string) *big.Int {
	return HashBytes([]byte(elt))
}

func Jump(nodeIdentifier big.Int, fingerentry int) *big.Int {
	var fingerentryBig = big.NewInt(int64(fingerentry))
	var jump = new(big.Int).Exp(two, fingerentryBig, nil)
	var sum = new(big.Int).Add(&nodeIdentifier, jump)

	return new(big.Int).Mod(sum, hashMod)
}

func Between(start, elt, end *big.Int, inclusive bool) bool {
	if end.Cmp(start) > 0 {
		return (start.Cmp(elt) < 0 && elt.Cmp(end) < 0) || (inclusive && elt.Cmp(end) == 0)
	} else {
		return start.Cmp(elt) < 0 || elt.Cmp(end) < 0 || (inclusive && elt.Cmp(end) == 0)
	}
}

func ObtainKeyBytes(keyPath string) ([]byte, error) {
	var content, errRead = os.ReadFile(keyPath)
	if errRead != nil {
		return nil, errRead
	}
	return content, nil
}

func ObtainSSHAuthentication(privateKeyPath string) (ssh.AuthMethod, error) {
	var content, errRead = ObtainKeyBytes(privateKeyPath)
	if errRead != nil {
		return nil, errRead
	}
	var key, parseErr = ssh.ParsePrivateKey(content)
	if parseErr != nil {
		return nil, parseErr
	}

	return ssh.PublicKeys(key), nil
}

func ObtainPubKey(path string) (*rsa.PublicKey, error) {
	var content, errRead = ObtainKeyBytes(path)
	if errRead != nil {
		return nil, errRead
	}

	var pemBlock, _ = pem.Decode(content)
	if pemBlock == nil {
		return nil, errors.New("rsa public key could not be extracted from pem block")
	}

	var pub, errParse = x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if errParse != nil {
		return nil, errParse
	}
	var pubKey, ok = pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("could not parse key to rsa key")
	}
	return pubKey, nil
}

type ChordRPCHandler int

func RpcServerInit(l *net.Listener) {
	var handler = new(ChordRPCHandler)
	rpc.Register(handler)
	rpc.HandleHTTP()
	go http.Serve(*l, nil)
}

func (t *ChordRPCHandler) Predecessor(empty string, reply *PredecessorRep) error {
	var node = Get()
	*reply = PredecessorRep{Predecessor: node.Predecessor}
	return nil
}
func (t *ChordRPCHandler) Successors(empty string, reply *SuccessorRep) error {
	var node = Get()
	*reply = SuccessorRep{Successors: node.Successors}
	return nil
}
func (t *ChordRPCHandler) FindSuccessor(args *big.Int, reply *FindSuccessorRep) error {
	var f, n = FindSuccessor(*args)
	*reply = FindSuccessorRep{Found: f, Node: n}
	return nil
}

func (t *ChordRPCHandler) Notify(args *NodeInfo, reply *string) error {
	Notify(*args)
	return nil
}

func (t *ChordRPCHandler) StoreFile(args *StoreFileArgs, reply *string) error {
	var key = args.Key.String()
	fmt.Printf("[rpcServerStoreFile] save file %v, content length %v", key, len(args.Content))
	var nodeKey = Get().Info.Identifier

	return NodeFileWrite(key, nodeKey.String(), args.Content)
}

func (t *ChordRPCHandler) FileTransfer(args *TransferFileArgs, reply *string) error {
	fmt.Printf("[rpcServerTransferFile] save %v number of files", len(args.Files))
	var nodeKey = Get().Info.Identifier
	var errs = NodeFilesWrite(nodeKey.String(), args.Files)
	if len(errs) > 0 {
		return errors.New("could not write the files")
	}
	return nil
}

func (t *ChordRPCHandler) MissingFiles(args *[]string, reply *[]string) error {
	fmt.Printf("[rpcServer] missing files with args: %v\n", *args)
	var nodeKey = Get().Info.Identifier
	var files, err = ListFiles(nodeKey.String())
	if err != nil {
		return err
	}
	var temp = ObtainExclusive(*args, files)
	fmt.Printf("[rpcServer] replying with: %v\n", temp)
	*reply = temp
	return nil
}

func (t *ChordRPCHandler) CheckAlive(empty string, reply *bool) error {
	*reply = true
	return nil
}

func ObtainExclusive[T comparable](arr1, arr2 []T) []T {
	var exclusive = []T{}
	for _, item1 := range arr1 {
		var found = false
		for _, item2 := range arr2 {
			if item1 == item2 {
				found = true
				break
			}
		}
		if !found {
			exclusive = append(exclusive, item1)
		}
	}
	return exclusive
}

func getConnection(nodeAddress NodeAddress) (*rpc.Client, error) {
	var client, err = rpc.DialHTTP("tcp", string(nodeAddress))
	return client, err
}

func handleCall[ArgT, RepT any](nodeAddress NodeAddress, method string, args *ArgT, reply *RepT) error {
	var client, err = getConnection(nodeAddress)
	if err != nil {
		return err
	}
	return client.Call(method, args, reply)
}
func Predecessor(node NodeAddress) (*NodeInfo, error) {
	var reply PredecessorRep
	var dummyArg = "empty"
	var err = handleCall(node, "ChordRPCHandler.Predecessor", &dummyArg, &reply)
	if err != nil {
		return nil, err
	}
	return reply.Predecessor, nil
}

func Successors(node NodeAddress) ([]NodeInfo, error) {
	var reply SuccessorRep
	var dummyArg = "empty"
	var err = handleCall(node, "ChordRPCHandler.Successors", &dummyArg, &reply)
	if err != nil {
		return nil, err
	}
	return reply.Successors, err
}
func ClientLocateSuccessor(node NodeAddress, id *big.Int) (*FindSuccessorRep, error) {
	var reply FindSuccessorRep
	var err = handleCall(node, "ChordRPCHandler.FindSuccessor", id, &reply)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
func ClientNotification(notifiee NodeAddress, notifier NodeInfo) error {
	var reply string
	var err = handleCall(notifiee, "ChordRPCHandler.Notify", &notifier, &reply)
	return err
}
func StoreFileClient(nodeAddress NodeAddress, fileKey big.Int, content []byte) error {
	var reply string
	var args = StoreFileArgs{Key: fileKey, Content: content}
	var err = handleCall(nodeAddress, "ChordRPCHandler.StoreFile", &args, &reply)
	return err
}

func FileTransfer(nodeAddress NodeAddress, files map[string]*[]byte) error {
	var reply string
	var args = TransferFileArgs{Files: files}
	var err = handleCall(nodeAddress, "ChordRPCHandler.FileTransfer", &args, &reply)
	return err
}

func MissingFiles(nodeAddress NodeAddress, files []string) ([]string, error) {
	var reply []string
	var err = handleCall(nodeAddress, "ChordRPCHandler.MissingFiles", &files, &reply)
	return reply, err
}

func CheckAlive(nodeAddress NodeAddress) bool {
	var dummy = "empty"
	var reply bool
	var err = handleCall(nodeAddress, "ChordRPCHandler.CheckAlive", &dummy, &reply)
	return err == nil && reply
}
func FileSending(address string, fileName string, fileContent []byte) error {

	var keyContent, errRead = ObtainKeyBytes(AUTHENTICATION_PUBLIC_KEY_PATH)
	if errRead != nil {
		return errRead
	}

	var publicKey, _, _, _, errParse = ssh.ParseAuthorizedKey(keyContent)
	if errParse != nil {
		return errParse
	}
	var pubKey, errPubKey = ssh.ParsePublicKey(publicKey.Marshal())
	if errPubKey != nil {
		return errPubKey
	}

	var authMethod, errAuth = ObtainSSHAuthentication(AUTHENTICATION_PRIVATE_KEY_PATH)
	if errAuth != nil {
		return errAuth
	}

	var configuration = ssh.ClientConfig{
		User:            USER,
		Auth:            []ssh.AuthMethod{authMethod},
		HostKeyCallback: ssh.FixedHostKey(pubKey),
	}

	var con, errCon = ssh.Dial("tcp", string(address), &configuration)
	if errCon != nil {
		fmt.Printf("[sftpClient.FileSending] Could not connect %v, err: %v\n", string(address), errCon)
		return errCon
	}
	fmt.Printf("[sftpClient.FileSending] Connection established to %v\n", string(address))

	con.SendRequest("keepalive", false, nil)

	var client, errClient = sftp.NewClient(con)
	if errClient != nil {
		fmt.Printf("[sftpClient.FileSending] Client Creation  %v, err: %v\n", string(address), errCon)
		return errClient
	}

	var filePath = filepath.Join("resources", fileName)

	var errMkdir = client.MkdirAll("resources")
	if errMkdir != nil {
		fmt.Printf("[sftpClient.FileSending] Directory Creation err: %v\n", errMkdir)
		return errMkdir
	}

	var file, errFile = client.Create(filePath)
	if errFile != nil {
		fmt.Printf("[sftpClient.FileSending] File Creation %v, err: %v\n", fileName, errCon)
		return errFile
	}

	var _, errWrite = file.ReadFrom(bytes.NewReader(fileContent))
	if errWrite != nil {
		fmt.Printf("[sftpClient.FileSending] File Write %v, err: %v\n", fileName, errCon)
		return errWrite
	}

	file.Close()
	client.Close()

	return nil
}

type FunctionSchedule func()

func Schedule(function FunctionSchedule, t time.Duration) {
	go func() {
		for {
			time.Sleep(t)
			function()
		}
	}()
}
