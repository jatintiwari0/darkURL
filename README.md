
# DarkURL

The **DarkURL** is a Python script used to generate homographs of Internationalized Domain Names (IDNs) to perform homograph attacks. A write-up covering the concept of this script can be found at my blog at [intothethickof.it](https://intothethickof.it/2023/08/15/generating-and-detecting-phishing-domains-with-idn-homograph-attacks).

The script uses a mapping of Unicode characters that are *visually-similar* to Latin letters to generate possible IDNs that can be used to impersonate traditional domains which only contain Latin letters.

Some use-cases include:
- Raising awareness on homograph attacks
- Generating phishing domains for internal phishing exercises
- Generating IDN homographs for your company/brand to register before bad actors do
  
The DarkURL is released under a BSD-style license. See
[LICENSE](LICENSE) for more details.

### CLONE
```
git clone https://github.com/UndeadSec/darkURL.git
```
### INSTALL
```
pip install python-nmap python-whois
```
### RUNNING
```
cd darkURL
```
```
python3 darkURL.py
```


### DISCLAIMER

TO BE USED FOR EDUCATIONAL PURPOSES ONLY

The use of the EvilURL is COMPLETE RESPONSIBILITY of the END-USER. Developer assume NO liability and are NOT responsible for any misuse or damage caused by this program.

"DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
Taken from [LICENSE](LICENSE).

