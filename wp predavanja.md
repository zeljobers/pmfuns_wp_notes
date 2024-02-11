# wp - Vladimir Kurbalija
# 1. nedelja
## prag za usmeni - 30/60 prakticne predispitne obaveze
- 1. 30 poena kolokvijum
- 2. 30 poena ili projekat ili kolokvijum - koji krajem semestra
> rade se na 3. spratu RC ucionice
- 3. 40 poena USMENI
## Popravni kolokvijumi 
- za odgovarajuci kolokvijum(ili oba) izlazimo u januaru i aprilu
## Projekat
- uslov 10 poena na kolokvijumu
- ako je ishodno bodovanje izrade projekta nezadovoljavajuce, onda regularno se radi drugi kolokvijuma 
    > kako to?
## Php (personal home page) - Rasmus Lerdorf 1994
- PHP 1 - c lib
- PHP 2 - 1995
- PHP 3 - ponovo izradjen kod i isporucen u junu '98.
- PHP 4 - Maj 2000.
  - Zend Engine (Zeev and Andy)
  - sesije, zapoceto oop, output buffering
- PHP 5 - Jul 2004
  - karakteristike kompletirano oop-a
- php 6 - preskoceno isporucivanje
- php 7 - decembar 2015. 
## Osobine
- dinamicnost
  - izmenljivost stranice kada svakim pogledom
  - interakcija sa korisnikom
- radi na web serveru, usluzuje Web stranice na zahtev
- umecemo php kod unutar html strane
- server side vs client
- interpretiran
## 26:00 - izvrsavanje
- ~~.html~~ .php
- kliktanjem na link ili preko URLa
  - Napomena : moguce je poslati web serveru podatke
- Web server prepoznaje url koji je .php skripta, a onda navodi php engine da procesuira i pokrene skriptu
  - Kada php engine zavrsi salje browseru **html stranicu**, a ne php!
## 31:00 - Zadatak PHP-a 
- cita, procesuira web formu od posetioca
- cita, pise, pravi fajlove na web serveru
- radi sa podacima iz db na web serveru
- hvata i procesuira podatke sa ostalih web sajtova i feedova
- generisanje dinamicke grafike, grafikona, izmenljivih fotografija
## Primena
- web forumi
- pretrazivaci
- CMS
- webmail
- ecommerce
## Prednosti
- Popularnosti 
  - ISP-ovi
  - web hostinzi
  - siroka masa programera
  - sajtovi
  - dokumentacija
- Cross-platform 
  - OS
  - Razvijanje, testiranje na jednom OS-u i isporuka na drugom
## Ostale web programming tehnologije ASP.NET, ASP,...
## Potreban softver
- Apache ili IIS Internet Information server - web server softver
- php server module
- db server
## Alternativan nacin za pokretanje PHPa
- na tudj web server - IIS, ngnix, GWS
- kompajliranje PHPa u c-u
- remote PHP server
## 43:00 - Primeri 
## 53:00 - Imenovanje $var pravila, pravljenje/deklaracija
- prvi karakter ili `_` ili slovo
- 56:40 - Dobra praksa, deklaracija sa inicijalizacijom
    - bez inic. je defaul vrednost `null`
## 59:30 - tipovi podataka
- nagovestavaju
  - kakve podatke sadrze
  - koliko memorije je potrebno za skladistenje tih podataka
- 2+1 grupe vrsta data type-ova
  - skalarne (Integer, Boolean, Float, String)
  - compound (Array, Object)
  - special (Resource - reference na fajlove i resurse, Null)
## 1:01:00 - Loose Typing
- tokom rada promenljiva sebi menja tip
- testiranje sa:
  - `gettype()`
  - `is_int()`,...
## Menjanje tipa promenljive
- `settype($var, "tip")`  
## Kastovanje - isto kao i u javi
- `echo` ***`(string)$var`***`."<br />"`
- moguce je i funkcijama kastovati u 3 tipa:
  - `intval(value)`
  - `floatval(value)`
  - `strval(value)`
## Operatori - isto
## Bitovski operatori
-...
- 1:14:00 - SKIP: je ovo, bitmaske, imaju neke konstante koje predstavljaju neke brojeve i tako to
## Operatori poredjenja
- `!=`, moze i `<>`
- `===` - ista vrednost, a i tip
- `!==`
- radi i poredjenje sa operandima string, tako sto ih kastuje
## Inkrementalni/dekrementirajuci
- `++$x`
## Logicki operatori
- false - takodje mogu biti i anulirajuci elementi na njegovom mestu
  ## Anulirajuci elementi
  - sve normalno, osim sto:
    - "0" - je nula string
## Konkatenacija niski `.`
## 1:23:30 - Prioriteti operatora
- **uoci da operator `||` i `or` postoje, ali `or` ima najmanji prioritet, cak i manji od `=`!!!**
## Konstante
- **Ne pocinje sa $**
- Dogovor je da sva velika slova pisemo 
- deklaracija sa inicijalizacijom : `define ("MOJA_KONSTANTA", 14)`

# 2. nedelja
## naredbe grananja
- PAZI! `else if` i  **`elseif`**(koristi ovaj), 0
  - ovaj prvi `else if` radi "neocekivano od podrazumevanog", npr. `if {} else if {} else {}` radice kao `if {} else {if {} else {}}`
- sve isto, nije diran `switch`
- ternirarni operator
## petlje
- sve isto, osim sto:
  - naredbom `break 2` moze da iskocimo i 2 nivoa ugnjezdenih petlji  
## stringovi
- pokriveni su dobro, s obzirom da se radi sa html web stranicama
- `""` i `''` koriste se za stringovi:
  - sa `""` ako se unutar stringa nalazi ime promenljive koja ga cuva, i njeno ime se isto u tom stringu menja
  - sa `""` upotreba escape sequence za unosenje spec. karaktera
  - sa `""` moze da se stavi unutar njih $var i da se evaluira, dok kod `''` ne
- 32:00 - sve esc seqs
-  string moze multiline da ode
-  ako je null nece ispisati nista
-  mogucnost `{$var}`, `${var}`
   -  ovo ce biti korisno ako se koristi u ovakve svrhe `echo "bruh : {$niz["bruh"]};"`
## rucno namesteni delimiteri za opis vrednost stringa
- *Heredoc* = `""`, DELIMITER se pise kako mi zelimo
  ```
  $myString = <<<DELIMITER
  ...string vrednost...
  DELIMITER;
  ```
- *Nowdoc* = `''`
  ```
  $myString = <<<'DELIMITER'
  ...string vrednost...
  DELIMITER;
  ```
## funkcije
- `strlen()`
- `str_word_count()`
- pristup karakteru
- osobina mutabilnosti stringa (moguca izmena karaktera)
- `substr()`, negativni brojevi za poziciju i duzinu imaju istu semantiku kao i u pythonu
- `strstr()` - string unutar stringa?
- `strpos()` - prva pojava, `strrpos()` -- poslednja pojava
  - neispravan nacin, jer 0 pokazuje pocetnu poziciju:
  >```
  >    $myString = "Hello, world!";
  >    if (!strpos($myString, "Hel")) echo "Not found";
  >```
  - ispavan nacin:
  >```
  >  $myString = "Hello, world!";
  >  if (false === strpos($myString, "Hel")) echo "Not found";
  >```
- `substr_count()` - koliko puta string unutar stringa?
- `strpbrk()` - za neku listu karaktera sumira koliko se puta pojavljuju unutar stringa
## zamena
- `str_replace()`
- `substr_replace()`
- `strtr()` - menja neke karaktere u stringu sa drugim karakterima
- `strtolower()`
- `strtoupper()`
- `ucfirst()` - prva slova menja 
- `lcfirst()` - prva slova menja 
- `ucwords()` - prva slova reci menja
> Pazi na case sensitivity sa `strstr()`, ali postoji i insensitive
- `stristr()` - nije case sensitive
## printf() i scanf()
- 1:08:00 - formatiranje
- 1:10:00 - mogucnost da se umetne ponavljanje karaktera `'`
  - pre `%'#8` i posle `%'#-8`
- floatovi 
  - `%.2f` - 2 decimale
  - `%012.2f` - ispisuje 12 cifara, a onde gde ih nema pise 0
  - `%12.2f` - ostavlja blanko
- stringovi
  - `%.8s` - izdvoji 8 karaktera
- upravljanje redosleda ispisa u formatiranju
  - `%3$d` - int pise koji je 3. parametar
- sprintf() daje povratnu vrednost stringa umesto da salje na stdout
- brisanje blankoa `trim()`,`ltrim()`,`rtrim()`
- str_pad
>```
>str_pad(string, 
>        duzina_koja_je_dozvoljena, 
>        string_koji_ce_da_popuni_prazninu_ponavljajuci_se)
>```
- wordwrap
>```
>wordwrap($str, 
>         *75_je_default*, 
>         *str_koji_bi_voleli_da_lomi_tekst*, 
>         *default_false_da_lomi_reci_duze_od_linije*)
>``` 
- resi prelamanje reci ukoliko se ogranici duzina linije
-  ali ovu funkciju moramo da obmotamo sa `<pre>... ovde wordwrap ...</pre>`
---
# 3. nedelja
## Nizovi
- lagodni za smestanje, opciono proizvoljnog i izmenljivog kapaciteta
- laka manipulacija sadrzajem
- element i indeks
- indeksirani `$authors = array("prvi", "drugi", "treci");` i asocijativni nizovi `$myBook = array("naslov" => "vredNas", "autor" => "Ja", "godina" => "2020");`
  - mogucnost dodavanja/zamena elementa u niz cistim indeksiranjem
    - dodavanje na kraj implicitno `$authors[] = "poslednji";`
    - **inicijalizacija npr. `$authors = array()` je dovoljna i bitna**
- Sve slicno i za asocijativni niz
## ispis nizova
- `print_r($niz)` - stampa niz u debuger-u
  -  ali kao drugi parametar moguce je samo postaviti true i ispisace string
## podniz - `array_slice($niz, $pocetak, [$duzina], [bool_za_indeksiranje_starog_niza])`
- `bool_za_indeksiranje_starog_niza` - ako je true, indeksi ce ostati isti
## brojanje - `count($niz)`
- napomena : da se pazi pri koriscenju `count-a` za pravljenje poslednjeg indeksa, jer je moguce da se preskoci nekoliko indeksa sve dok ne bude taj poslednji na redu
## Koracanje kroz niz (kao iteratori) - ima ugradjeni pokazivac koji inicijalno pokazuje na pocetak
- `current()` - vrednost i `key()` - indeks
- `next(), prev(), reset(), end()` - pomera pokazivac i vraca vrednost
- sta ako u nizu postoji vrednost `false` i funkcije mogu biti dvosmislene u tom slucaju je resenje:
  - `each()` - vraca element u vidu niza i next-uje pointer
    - niz sadrzi 4 vrednosti medju kojima pod kljucevima `0, "kljuc", 1 i "vrednost"`
    - ako ne nadje nista vraca se `false`

## foreach - petlja kroz niz i objekat
- 2 nacina :
  - sve vrednosti elemenata
  - svi kljucevi i vrednosti elemenata
```
// foreach( $niz as $vrednost) {
foreach( $niz as $kljuc => $vrednost) {
  ...
}
```
> da l' onaj pokazivac unutar niza se resetuje ili ostaje na zadnjem elementu?
- Nema brigekod rupa bez indeksa u nizu
- Pazi na to da se radi **duboko kopiranje** unutar $vrednost
  - moguce je ovo izmanipulisati da bude **plitko kopiranje** koriscenjem **reference** na vrednost niza:  `foreach( $niz as & $vrednost) {`
  - nakon toga radi se `unset($vrednost)`, da bi otkacili referencu zarad bezbednosti

## Visedimenzionalni nizovi
`$matrix = array(array("ime"=> ...,  "prezime" => ...), array("ime"=> ...,  "prezime" => ...), ...)`
- koriscenje ugnjezdenih petlji...
## Nastavak kasnije...
---
## Query strings(URL), cookies(na browseru), sessions(cuvaju na serveru)
- po svojoj podrazumevanoj nameni web server ne cuva nikakve prethodne parametre
- ali javlja se potreba...
## Query strings namena - pamcenje tokom pretrazivanja, biranje tema unutar bloga/foruma
## Sigurnost query stringova
- vidljivi kroz url
- losi za autentifikaciju
`http://.../... .php?param1=Bruh&param2=This+is+a+certified+hood+classic`
- dozvoljeni karakteri "(-|[_.*',a-zA-Z0-9])" i + 'blanko' i % 'UTFcode'
### 1:04:00 - `urlencode()` i `urldecode()` - obrada sa % za nedozovoljene karaktere u url
- bolja funkcija za ovo `http_build_query($niz)`
  - uzima asocijativan niz pretvara u string
- dodatno, obrada iz `&` u `&amp;` : ***`httpspecialchars(`***`http_build_query($niz))`
## Preuzimanje iz querystringa unutar php skripta
### `$_GET["param1"]` superglobalan niz
- 1:15:00 - Vazno je ispratiti tipove
---
# 4. nedelja
## Funkcija
- podrutina - blok koda koji izvrsava neki zadatak
- define and invoke it
- mogucnost vise argumenata
- povratna vrednost
## prednosti fja
- duplo pisanje koda izbegnuto
- olaksano debagovanje
- primenljvost svuda
- modularnost
## mogucnost da se ime fje upise u string var i onda njime da se pozove 
> da li je moguce da se tako unutar `""` pozove funkcija sa `$strKojiDrziImeFje(...)`?
  - ne, zato sto ce ispisati njegovo ime i argument
## Pisanje i poziv funkcije primer
- mogucnost podrazumevana vrednost parametra: `function mojaFja($param1 = defVrednost) {...}`
- pri slanju nardbe povratne vrednosti `return` odmah PHP engine izlazi iz fje
## Dosezi promenljivih
- lokalne promenljive
- globalne promenljive
  - promenljive van funkcija
  - promenljive unutar funkcija sa modifikatorom dosega `global`
  - kao element ugradjene promenljive asocijativnog niza `$GLOBALS["..."]`
## Zivotni vek promenljivih
- staticka lokalna promenljiva
  - pamti stanje unutar funkcije za bilo koji njen poziv
  - njeno deklarisanje zahteva inicijalizovanje
## Anonimne fje
- 2 namene:
  1. dinamicki tokom rada moze se generisati njen kod
  2. kratkotrajnost, callbackovi/handleri

- ovo je neka zasebna mogucnost `$mode = "+";` i to je mogucnost pristupa dinamicnosti
  - dati promenljivu operatoru
- `$processSum = create_function('$a, $b', "return \$a $mode \$b");`
  - parametri koji se prosledjuju unutar anon fje su u nowdoc stringu nabrojani u prvom parametru ove fje
  - kod dinamicke fje u heredoc-u
- poziv `echo $processSum(2,3);`
  ## Primer fje
- pravimo komparator za fju iz STL-a `usort()`
  - kome su parametri niz i callback fja
  - callback ima $a, $b parametre i vraca:
    - negativnu vrednost kad $b > $a
    - ...
    - ...
  - po duzini reci, `usort($words, create_function('$a, $b', 'return strlen($a) - strlen($b)'));`
## Rad sa referencama (precica, alias)
- da namestimo sa deep kopije na shallow
- kao parametri u funkcijama
- kao povratna vrednost funkcije, koristi se sa promenljivama
- IZRAZ BEZ SMESTANJA NJEGOVOG REZULTATA U PROMENLJIVU NE SME DA SE REFERENCIRA!
## rekurzivne fje - bazni slucaj i rekurzivni slucaj
---
# 5. nedelja
## Klase i objekti
- objekti se salju referencama, stoga radi plitko kopiranje. tako da, treba da se obrati paznja da ne uradimo nezeljenu izmenu.
```php
class Car {
  ...
}
$beetle = new Car();
print_r($beetle);
```
## modifikatori pristupa
  - public
  - private - unutar klase samo pristup
  - protected - kao private, ali svaka klasa koja nasledi ovu dobija pristup 
  > Preporuka : za sve property-e da bude private i napraviti getter/setter-e
## polja ovde zovu **property**
- pristup `$object->property;`
##  Staticke osobine
```php
class Car {
  static public $polje;
  ... 
}
```
- staticki clanovi klase su nezavisni od bilo kog objekta instanciranog iz klase
- njima pristupas sa `Car::$polje`
## Konstante u klasi
```php
class MyClass {
  const MYCONST = 123; // nije kao uobicajeno sa define("NEKI_CONST", ...);
  ...
}
```
- pristup : `echo MyClass::MYCONST;`
- moje zapazanje : ne mora instanciranje nikakvo da se radi
## Metode
```php
class MyClass {
  public function aMethod() {
    ...
  }
  ...
}
$obj = new MyClass();
$obj->hello(); // pristup
```
- modifikator pristupa je podrazumevano `public`
## Pristup elementu u klasnom objektu unutar iste klase u nekoj njenoj metodi
`... echo $this->nekiELementKlase ...`
## Staticke metode
```php
class MyClass {
  public static function aMethod() {
    ...
  }
  ...
}
MyClass::aMethod();
```
## Pristup statickom elementu u klasi unutar iste klase u nekoj njenoj metodi
- za promenljive : `MyClass::$var` ili `self::$var`
- za konstante : `MyClass::MYCONST` ili `self::MYCONST`

## 11:00 - PHP slabo, lako tipiziran, loosely typed 
- Izlazi greska: Pristup elementima objekata se radi na nekom drugom tipu, npr. String
- pa je jedno od delimicnih resenja: da u `public function paint(Car $car, $color)` za `Car $car` navedemo tip
  - isto je moguce to uraditi i za `function neka_fja(array $niz)`, *a za druge tipove ne!*
## Predefenisanje (Overloading) sa `__get(), __set(), __call()`
- kako objekat funkcionise?
  - pristup property-u - u stvari hvata vrednost elementa iz asocijativnog niza
  - pisanje u proprerty - u stvari pise u db polje
  - zvanje metoda - u stvari metod se ne nalazi u objektu i zove neki drugi metod
- primer
  - `__get()`
  ```php
  class Car {
    ...
    public $color;
    ...
    public function __get($propertyName) {
      echo "ispisi ovo '$propertyName' hahahaha "
      return "blue";
    }
    ...
  }
  $car = new Car();
  $x = $car->color;
    // ispisuje "ispisi ovo 'color'"
  echo "The car's color is $x";
    // ispisuje "The car's color is blue."
  ```
  - `__set($propertyName, $propertyValue)` - nema povratnu vrednost
  - `__call($methodName, $arguments) {`
  ```php
      ... 
      return $returnVal;
    }
  ```
## Ostale metode moguce za predefenisanje ponasanja
- `__isset()`
- `__unset()`
- `__callStatic()`
> sada je ovo ocigledno po nazivima postojecih fja za ova 2 prva, a za zadnji je slican `__call()`-u...
## Nasledjivanje
```php 
class Shape {...}
class Circle extends Shape {...}
```
- Overriding
- zvanje metoda iz nadklase sa `parent::NekiMetod()`
- zabranjivanje nasledjivanja klase sa keywordom **`final`** `class Klasa {...}`
  - pa ako se ipak proba, izbice greska
## Apstraktna klasa 
- `abstract class Ime { abstract function ImeMetoda() {...} ... } `
- Nemogucnost instanciranja
- ako je nasledi ne-apstraktna klasa : zahteva se definisanje svega  
  - inace, moze biti pola-definisano, pola-ne
## Interfejsi
- Mogu se vise njih implementirati u klasu
- Nemaju properties-e, samo deklaracije metoda
- sve public
> Da li mogu da sadrze konstante?
```php
interface MojInterface {
  ...
}

class MojaClass implements MojInterface {
  ...
}
```
## Konstruktori
```php
class Klasa {
  function __construct() {
    echo "Bababoey <br />";
  }
}
$obj = new MyClass;
```
- jedan konstruktor
> znaci da ne moze da se overloaduje?
- slanje parametara kroz konstruktor
- pristupanje nadklasnom konstruktoru `parent::__construct()`
## Destruktor
- objekat se brise kada:
  - nema referenci vezanih za njega 
  - skripta izadje ili nastalom greskom
- `function __destruct() {...brisi...}`
## Citanje klasnih fajlova
- preporuka je da se klase drze u razlicitim fajlovima
- Klasa.php -> class Klasa 
```php
<?php 
  require_once("putanja")
  $p = new Person();
?>
``` 
## `serialize()` (`__sleep()`) i `deserialize()` (`__wakeup()`)
- serijalizacija u neki string koji opisuje objekat
- i naopacke
- i njihovi override-ovi

## `get_class($obj)` i `$obj instanceof ClassName`
---


# 6. nedelja - forma
- svi moguci alati forme
- `$_REQUEST` - automatski radi za POST/GET/COOKIE
- multi-value fields za select pisemo `...name=multiValue[]...`
- za rad sa fajlovima mora se pisati `<form ... enctype="multipart/form-data">`
  - biranje fajla: `<input type="file" name="fileSelectField" id="fileSelectField" value="">`
    - pristup : `$_FILES["fileSelectField"][imePolja]` gde `imePolja`:
      - `name`,
      - `type`, 
      - `size`,
      - `tmp_name`,
      - `error` - konstante koje vracaju info o gresci
  - ogranicavanje velicine unetog fajla
    - php.ini
    - hidden form field sa `name="MAX_FILE_SIZE"`
      - ovaj pristup je moguce zlonamerno iskoristiti
    - pristupom na `size` i proverom radimo die
- redirekcija: `header("Locaion: saijfoaijf.html");`
  - mora da bude skroz iznad!
---
# 7. nedelja - cookies i sesije
- cookies 
  - max 4KB unutar browsera
  - salje se unutar requesta
  - doprmeljen cookie od servera klijentu je moguc da se koristi unutar skripti
  - ipak ih je moguce razotkriti napadom
  -  `name`, `value`, `expires` - moze i da prestane kad se ugasi browser, ali inace po UNIX formatu, `path` - gde se nazad salje cookie, `domain` - za onaj server koji je poslao cookie, navodi se gde je, `secure` - https, `HttpOnly` - ako true, js ne moze nista
  -  `header("Set-Cookie:...")` 7 parametara, ali barem 4: name,value, expires, path
    - ***ali ovako isto `setcookie("fontSize", 3, time() + 60*60*24*365, "/", ".example.com", false, true)`***
   -  asocijativan niz if(issset(`$_COOKIE["pageViews"]`))
   -  brisanje cookies je samo umetanje praznog string vrednosti sa expire-om `<= 0`
- sesije
  - cuvaju se na serveru
  - sessionID
  - php.ini session.save_path - folder gde je sesija
    - echo `ini_get("session.save_path")`
  - info o interakciji korisnika
  - zivotni vek : gasenje browsera
  - `session_start()` - iznad svih ovu direktivu pisati
    - `PHPSESSID` browser sekcija za cookie
  - `$_SESSION[]` - moze i obican tip, a i objekat
  - `session_destroy()`
- `session_name()` - jednostavno je koristiti za brisanje samo ovim za jedan session
- funkcja sa bez mogucnosti cookies
  - queryString - nesigurno
- `session_id()`
---
# 8. nedelja
- PDO i mysqli
- `$con = new PDO(`
  - database source name - dsn
  - username
  - password
- `$conn = null` - zatvaranje konekcije
- `PDOExceptions`: `$con->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);`
  - `try {} catch (Exception $e) { echo e->getMessage(); }`
- `$rows = $con->query($sql)` - pristup entitetu pojedinacno `foreach-om`
- binding - host promenljive 
  ```php
  $id =...;
  $name = ...;
  $password = ...;
  $sql = "INSERT INTO member VALUES (:id,:name,
   password(:password))"
  // parsiranje naredbe
  $st = $con->prepare($sql);
  try{
    $st->bindValue(":id", $id, $id, PDO::PARAM_INT);
    ... // za sve
    $st->execute();
  } catch (PDOException $e) {...}
  ```
- primeri za update, delete

## nizovi
- asort, arsort - sort po vrednosti
- ksort, krsort - sort po kljucu
- array_multisort odjednom
- array_unshift() start / push end, array_shift() / pop
  - ubacivanje novog niza ubacice citav ugnjezden niz u 1 element kao vrednost
- array_splice()
- array_merge()
- explode - kao split
- implode - join
- `list ($title, $author, $year) = $myBook`
- `while(list($key, $value) = $each(myBook)) {...}`

# 9. nedelja - File i folderi
- file_exists($path)
- filesize($path)
- filea/c/mtime()
- getdate()
- basename() - daje samo ime fajla, cak moze i bez ekstenzije
- fopen($path, "rb") - b znaci da se smatra kao binarni, t kao text(windows return carriage)
- fclose($f)
- 26:00 razne fje i primeri
- copy, rename, unlink
- opendir, closedir, readdir
- rewinddir(), chdir(), mkdir(), rmdir(), dirname(), is_dir(), is_file()