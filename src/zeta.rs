use crate::params::N_PARAM;

pub const ZETAS: [i32; N_PARAM / 2] = [535035897, 291855948, 245531879, 451275271, 230785569,
    460366806, 163250384, 428887601, 161614173, 3016246, 401135695,
    142852922, 36374899, 440875564, 271901421, 324618495, 155560971,
    18683939, 286197179, 396534730, 325250990, 12864518, 299880520,
    364837051, 191887299, 504880003, 318654797, 341944753, 115818287,
    304589863, 58352146, 24801698, 273971213, 52504239, 298022356, 389146723,
    426069971, 3625667, 411423014, 415300031, 49665814, 142871421, 113514562,
    425697888, 457645931, 165794627, 397781160, 344611024, 105268009,
    323961521, 119337902, 274379108, 452711568, 37844625, 365333605,
    76429455, 160792878, 119316486, 215671609, 242902772, 499965556,
    32887091, 42674384, 109148771, 120790899, 437214915, 155788300,
    439801726, 407320441, 465018045, 189668769, 406502175, 213645922,
    106769463, 215691871, 209288662, 320477096, 75881552, 37876718,
    163249801, 227710913, 354960821, 149297030, 245795045, 14444057,
    181223934, 296447107, 54015951, 213624898, 171550291, 466181780,
    222297567, 512187262, 293163671, 150412954, 454021040, 35583785,
    532343271, 3409814, 108735845, 234238490, 362391466, 303786424,
    247140090, 451805640, 295662117, 478258120, 181403514, 204213991,
    264869256, 326707660, 532997498, 48717705, 303073751, 212079379,
    159926173, 441170303, 72182496, 285493813, 41443378, 138152971,
    537024964, 96754455, 99939592, 402977724, 8734453, 147773159, 165014718,
    272630837, 464341688, 359316607, 303067592, 6220304, 43571659, 296809387,
    178777034, 16705795, 314064416, 476750829, 166854583, 118604030,
    338058654, 89690079, 114596682, 186639367, 78469819, 244580498,
    296990563, 426361503, 256041408, 134506890, 123212045, 9415545,
    127232480, 340671296, 12174459, 469599494, 299742091, 172684343,
    390851084, 462523306, 311143884, 495738607, 369370984, 125161331,
    436624682, 292576847, 359064695, 348221659, 514202178, 441904554,
    94506853, 179371296, 244849520, 432045702, 521702650, 36281564,
    528063867, 384811105, 152254944, 225528737, 368371585, 388464262,
    492350040, 70263113, 192301642, 500647842, 74404265, 426555021,
    309100650, 482775606, 146490849, 419767975, 40492335, 157247695,
    53352823, 324514569, 100442746, 115779212, 359075573, 243997280,
    94515457, 233484280, 22936622, 188938498, 187555870, 149545280,
    462545427, 152635371, 245387090, 499327529, 355032090, 16083331,
    257657009, 164743100, 54122754, 526934180, 18128737, 179390902,
    229607812, 144535677, 345691310, 129965484, 146803296, 319986435,
    92949900, 150925195, 61831992, 271429914, 188444896, 525044113,
    518348290, 423812492, 5332727, 437879545, 258003078, 433002161, 32663443,
    417712927, 174792585, 346792366, 54317884, 401032557, 237662079,
    21386734, 373445957, 252263998, 255422408, 113131923, 427335609,
    422045900, 327538087, 218305419, 514480367, 310188935, 138160242,
    485992370, 64602652, 275137354, 401850000, 197123769, 338521864,
    405075672, 513609609, 209539475, 340315109, 386319602, 142853387,
    450604622, 10962757, 122419384, 113281652, 475645634, 183814444,
    31302683, 300808753, 485623268, 3170486, 512925015, 227234133, 178490159,
    317646499, 468779633, 90938172, 209001229, 273558092, 211437766, 2792558,
    221025559, 389038023, 122491435, 406024869, 314145891, 182412665,
    74967915, 472576279, 409970333, 315668538, 515800998, 536949922,
    27461602, 448602811, 237674995, 462158158, 303152714, 443467318,
    168687096, 395838112, 82274708, 456471730, 95510351, 29551280, 528749182,
    308514670, 427490135, 75606112, 432438783, 283297286, 318358026,
    316498606, 23790953, 172624889, 182180034, 6039384, 138577629, 267441715,
    423888408, 34257934, 462627893, 203592217, 461433523, 99526822,
    394174017, 389443158, 531601253, 200559997, 203362074, 246404906,
    522695176, 340149355, 445527317, 535816745, 161468085, 386932376,
    482918626, 365981154, 111742576, 253756735, 144122092, 18576118,
    363089862, 112662142, 13905906, 123269485, 105998456, 197357682,
    130071321, 466046662, 332721000, 261423837, 184630621, 471724110,
    109297596, 205836259, 84446041, 99885417, 219582180, 484141128,
    181023400, 181395006, 63832983, 179031195, 320635459, 348757131,
    520924272, 534204331, 138109071, 200973200, 335802017, 85510288,
    469519297, 179463110, 309587832, 87776184, 209222898, 283308787,
    102563196, 241221121, 526041356, 184063228, 95719216, 469954329,
    277177796, 378572419, 151309908, 529415806, 311624716, 311530549,
    57624048, 80704972, 505354092, 392730023, 484900259, 468419075,
    101354184, 465349940, 417541902, 102603499, 55682233, 320560555,
    290756036, 242832948, 203882715, 208495773, 444365764, 261038694,
    91111529, 396200615, 363666724, 342488627, 26003571, 305570326, 99919114,
    165622811, 372321435, 341984325, 142969236, 52095171, 496452398,
    276920306, 500033309, 23502147, 149612416, 101980447, 494633998,
    163581214, 492006168, 163400501, 288185682, 146081674, 491409928,
    184795110, 287117794, 210474914, 445740323, 121686053, 341316746,
    253445618, 424212640, 150352219, 484187312, 124556692, 193195205,
    363756134, 150063160, 474123608, 55828372, 31834529, 486959995,
    163520948, 171665553, 498333137, 219794197, 351537194, 5282130,
    474123584, 491892892, 93439073, 78363806, 376800468, 84368998, 379278305,
    387512369, 24884611, 182342074, 433037612, 220297834, 298573929,
    464094142, 276950433, 259436117, 431298258, 445013616, 425212130,
    101894783, 258231868, 376479275, 138017716, 174433663, 237958275,
    511371892, 251712156, 10620231, 486064111, 38926790, 506118469,
    490865712, 412971015, 242382558, 155812424, 439561802, 517671585,
    67543497, 21401135, 312729932, 302170551, 223864052, 278159880,
    397322892, 242143980, 455298125, 13236130];